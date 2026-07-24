use rcgen::{CertificateParams, DistinguishedName, KeyPair, SanType};

pub const SIGNER_NAME: &str = "example.com/signet";
pub const TRUST_DOMAIN: &str = "example.com";
pub const USERNAME: &str = "system:serviceaccount:workloads:example-app";
pub const IDENTITY: &str = "spiffe://example.com/ns/workloads/sa/example-app";
pub const USAGES: [&str; 3] = ["digital signature", "server auth", "client auth"];

pub fn csr_with_sans(sans: Vec<SanType>) -> Vec<u8> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("test Ed25519 key generation");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("test CSR params");
    params.distinguished_name = DistinguishedName::new();
    params.subject_alt_names = sans;
    params
        .serialize_request(&key)
        .expect("test CSR generation")
        .pem()
        .expect("test CSR PEM")
        .into_bytes()
}

pub fn valid_csr() -> Vec<u8> {
    csr_with_sans(vec![SanType::URI(
        IDENTITY.try_into().expect("test SPIFFE URI"),
    )])
}
