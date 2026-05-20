use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use const_oid::db::rfc4519::COMMON_NAME;
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use x509_cert::name::Name;
use x509_cert::Certificate;

use crate::binary::{BinaryFormat, BinaryView};

#[derive(Clone, Debug)]
pub struct SignatureInfo {
    pub signer_cn: Option<String>,
    pub signer_o: Option<String>,
    pub issuer_cn: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub serial_hex: Option<String>,
    pub raw_size: usize,
    pub parse_error: Option<String>,
}

impl SignatureInfo {
    pub fn signed_unparsed(raw_size: usize, err: String) -> Self {
        Self {
            signer_cn: None,
            signer_o: None,
            issuer_cn: None,
            not_before: None,
            not_after: None,
            serial_hex: None,
            raw_size,
            parse_error: Some(err),
        }
    }
}

pub fn detect(view: &BinaryView<'_>) -> Option<SignatureInfo> {
    if view.format != BinaryFormat::Pe {
        return None;
    }
    let pe = goblin::pe::PE::parse(view.bytes).ok()?;
    let opt = pe.header.optional_header.as_ref()?;
    let dir = opt.data_directories.get_certificate_table()?;
    if dir.size == 0 || dir.virtual_address == 0 {
        return None;
    }
    // Security directory: virtual_address is a file offset (not an RVA).
    let start = dir.virtual_address as usize;
    let total_size = dir.size as usize;
    let blob = view.bytes.get(start..start.saturating_add(total_size))?;

    // WIN_CERTIFICATE: dwLength(4) + wRevision(2) + wCertificateType(2) + bCertificate[]
    if blob.len() < 8 {
        return Some(SignatureInfo::signed_unparsed(total_size, "blob too small".into()));
    }
    let dw_length = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    let cert_type = u16::from_le_bytes([blob[6], blob[7]]);
    // WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
    if cert_type != 0x0002 {
        return Some(SignatureInfo::signed_unparsed(
            total_size,
            format!("non-PKCS#7 wCertificateType 0x{:04x}", cert_type),
        ));
    }
    let end = dw_length.min(blob.len());
    if end <= 8 {
        return Some(SignatureInfo::signed_unparsed(total_size, "dwLength too small".into()));
    }
    let pkcs7_with_pad = &blob[8..end];
    let pkcs7 = match der_seq_total_len(pkcs7_with_pad) {
        Some(n) if n <= pkcs7_with_pad.len() => &pkcs7_with_pad[..n],
        _ => pkcs7_with_pad,
    };

    match parse_cms(pkcs7) {
        Ok(info) => Some(SignatureInfo {
            raw_size: total_size,
            ..info
        }),
        Err(e) => Some(SignatureInfo::signed_unparsed(total_size, e)),
    }
}

fn parse_cms(der_bytes: &[u8]) -> Result<SignatureInfo, String> {
    let ci = ContentInfo::from_der(der_bytes).map_err(|e| format!("ContentInfo: {}", e))?;
    let inner = ci
        .content
        .to_der()
        .map_err(|e| format!("Content re-encode: {}", e))?;
    let sd = SignedData::from_der(&inner).map_err(|e| format!("SignedData: {}", e))?;

    let signer_cert = pick_signer_cert(&sd);

    let mut info = SignatureInfo {
        signer_cn: None,
        signer_o: None,
        issuer_cn: None,
        not_before: None,
        not_after: None,
        serial_hex: None,
        raw_size: 0,
        parse_error: None,
    };

    if let Some(cert) = signer_cert {
        info.signer_cn = first_rdn_value(&cert.tbs_certificate.subject, COMMON_NAME);
        info.signer_o = first_rdn_value(
            &cert.tbs_certificate.subject,
            ObjectIdentifier::new_unwrap("2.5.4.10"),
        );
        info.issuer_cn = first_rdn_value(&cert.tbs_certificate.issuer, COMMON_NAME);
        info.not_before = Some(format!("{}", cert.tbs_certificate.validity.not_before));
        info.not_after = Some(format!("{}", cert.tbs_certificate.validity.not_after));
        info.serial_hex = Some(hex_lower(cert.tbs_certificate.serial_number.as_bytes()));
    }

    Ok(info)
}

fn pick_signer_cert(sd: &SignedData) -> Option<Certificate> {
    let certs = sd.certificates.as_ref()?;
    let signer_info = sd.signer_infos.0.as_slice().first()?;
    for choice in certs.0.iter() {
        if let cms::cert::CertificateChoices::Certificate(cert) = choice {
            if matches_signer(cert, signer_info) {
                return Some(cert.clone());
            }
        }
    }
    for choice in certs.0.iter() {
        if let cms::cert::CertificateChoices::Certificate(cert) = choice {
            return Some(cert.clone());
        }
    }
    None
}

fn matches_signer(cert: &Certificate, info: &cms::signed_data::SignerInfo) -> bool {
    use cms::cert::IssuerAndSerialNumber;
    use cms::signed_data::SignerIdentifier;
    match &info.sid {
        SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber { issuer, serial_number }) => {
            cert.tbs_certificate.issuer == *issuer
                && cert.tbs_certificate.serial_number.as_bytes() == serial_number.as_bytes()
        }
        SignerIdentifier::SubjectKeyIdentifier(_) => false,
    }
}

fn first_rdn_value(name: &Name, oid: ObjectIdentifier) -> Option<String> {
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == oid {
                if let Ok(s) = atv.value.decode_as::<der::asn1::PrintableStringRef>() {
                    return Some(s.to_string());
                }
                if let Ok(s) = atv.value.decode_as::<der::asn1::Utf8StringRef>() {
                    return Some(s.to_string());
                }
                if let Ok(s) = atv.value.decode_as::<der::asn1::Ia5StringRef>() {
                    return Some(s.to_string());
                }
                if let Ok(s) = atv.value.decode_as::<der::asn1::TeletexStringRef>() {
                    return Some(s.to_string());
                }
                if let Ok(s) = atv.value.decode_as::<der::asn1::BmpString>() {
                    return Some(format!("{}", s));
                }
            }
        }
    }
    None
}

fn der_seq_total_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 2 || bytes[0] != 0x30 {
        return None;
    }
    let len_byte = bytes[1];
    if len_byte & 0x80 == 0 {
        return Some(2 + len_byte as usize);
    }
    let n = (len_byte & 0x7f) as usize;
    if n == 0 || n > 8 || bytes.len() < 2 + n {
        return None;
    }
    let mut content_len = 0usize;
    for i in 0..n {
        content_len = (content_len << 8) | bytes[2 + i] as usize;
    }
    Some(2 + n + content_len)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}
