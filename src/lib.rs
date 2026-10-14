#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
use aes::cipher::block_padding::{NoPadding, Pkcs7};
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use lopdf::xref::{XrefEntry, XrefType};
use lopdf::{Dictionary, Document, Object, ObjectId, Reader, StringFormat};
use md5::{Digest, Md5};
use sha2::{Sha256, Sha384, Sha512};
use std::cell::RefCell;
use std::collections::HashSet;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Standard PDF password padding bytes (Table 21, §7.6.3.3)
const PADDING: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
    0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ========================== RC4 ==========================

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut state = [0u8; 256];
    for (i, v) in state.iter_mut().enumerate() {
        *v = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
        state.swap(i, j as usize);
    }
    let mut out = vec![0u8; data.len()];
    let (mut ii, mut jj): (u8, u8) = (0, 0);
    for (idx, &byte) in data.iter().enumerate() {
        ii = ii.wrapping_add(1);
        jj = jj.wrapping_add(state[ii as usize]);
        state.swap(ii as usize, jj as usize);
        out[idx] = byte ^ state[(state[ii as usize].wrapping_add(state[jj as usize])) as usize];
    }
    out
}

// ========================== AES ==========================

/// AES-CBC as PDF uses it for strings and streams (§7.6.3.1): the 16-byte IV
/// is stored in front of the ciphertext, and the plaintext is PKCS#5-padded.
/// The key length picks AES-128 (AESV2) or AES-256 (AESV3).
fn aes_cbc_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    // An IV and nothing else is how an empty string is sometimes written.
    if data.len() <= 16 {
        return Vec::new();
    }
    let (iv, body) = data.split_at(16);
    // A body that is not whole blocks is malformed. Decrypt the whole blocks
    // rather than refuse the file, the way PDF readers do.
    let body = &body[..body.len() - body.len() % 16];
    if body.is_empty() {
        return Vec::new();
    }
    let padded = match key.len() {
        16 => Aes128CbcDec::new_from_slices(key, iv).ok().and_then(|c| c.decrypt_padded_vec_mut::<Pkcs7>(body).ok()),
        32 => Aes256CbcDec::new_from_slices(key, iv).ok().and_then(|c| c.decrypt_padded_vec_mut::<Pkcs7>(body).ok()),
        _ => None,
    };
    // Some writers get the padding wrong. Keep the plaintext with the padding
    // left on, rather than lose the object.
    padded
        .or_else(|| match key.len() {
            16 => Aes128CbcDec::new_from_slices(key, iv).ok().and_then(|c| c.decrypt_padded_vec_mut::<NoPadding>(body).ok()),
            32 => Aes256CbcDec::new_from_slices(key, iv).ok().and_then(|c| c.decrypt_padded_vec_mut::<NoPadding>(body).ok()),
            _ => None,
        })
        .unwrap_or_else(|| data.to_vec())
}

/// AES-256 with a zero IV and no padding: how /UE and /OE wrap the file key (§7.6.4.3.3).
fn aes256_unwrap(key: &[u8], wrapped: &[u8]) -> Option<Vec<u8>> {
    Aes256CbcDec::new_from_slices(key, &[0u8; 16])
        .ok()?
        .decrypt_padded_vec_mut::<NoPadding>(wrapped)
        .ok()
}

// ========================== PDF Encryption Primitives ==========================

fn pad_password(password: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 32];
    let len = password.len().min(32);
    padded[..len].copy_from_slice(&password[..len]);
    if len < 32 {
        padded[len..].copy_from_slice(&PADDING[..32 - len]);
    }
    padded
}

/// Algorithm 3.3 — compute the O (owner) value
fn compute_o_value(owner_pwd: &[u8], user_pwd: &[u8], key_len: usize, rev: i64) -> Vec<u8> {
    let padded = pad_password(if owner_pwd.is_empty() { user_pwd } else { owner_pwd });
    let mut hash = Md5::digest(padded).to_vec();
    if rev >= 3 {
        for _ in 0..50 {
            hash = Md5::digest(&hash[..key_len]).to_vec();
        }
    }
    let rc4_key = &hash[..key_len];
    let mut result = rc4(rc4_key, &pad_password(user_pwd));
    if rev >= 3 {
        for i in 1..=19u8 {
            let xk: Vec<u8> = rc4_key.iter().map(|b| b ^ i).collect();
            result = rc4(&xk, &result);
        }
    }
    result
}

/// Algorithm 3.2 — compute the file encryption key (revisions 2–4)
fn compute_encryption_key(
    user_pwd: &[u8],
    o_value: &[u8],
    perms: i32,
    file_id: &[u8],
    key_len: usize,
    rev: i64,
    encrypt_metadata: bool,
) -> Vec<u8> {
    let mut ctx = Md5::new();
    ctx.update(pad_password(user_pwd));
    ctx.update(o_value);
    ctx.update((perms as u32).to_le_bytes());
    ctx.update(file_id);
    // Step (f): only when the document metadata is left unencrypted.
    if rev >= 4 && !encrypt_metadata {
        ctx.update([0xFF; 4]);
    }
    let mut hash = ctx.finalize().to_vec();
    if rev >= 3 {
        for _ in 0..50 {
            hash = Md5::digest(&hash[..key_len]).to_vec();
        }
    }
    hash.truncate(key_len);
    hash
}

/// Algorithm 3.4 / 3.5 — compute the U (user) value
fn compute_u_value(enc_key: &[u8], file_id: &[u8], rev: i64) -> Vec<u8> {
    if rev == 2 {
        rc4(enc_key, &PADDING)
    } else {
        let mut ctx = Md5::new();
        ctx.update(PADDING);
        ctx.update(file_id);
        let mut result = rc4(enc_key, &ctx.finalize());
        for i in 1..=19u8 {
            let xk: Vec<u8> = enc_key.iter().map(|b| b ^ i).collect();
            result = rc4(&xk, &result);
        }
        result.resize(32, 0);
        result
    }
}

/// Per-object encryption key (§7.6.2)
fn object_key(base: &[u8], obj_num: u32, gen_num: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(base.len() + 5);
    buf.extend_from_slice(base);
    buf.extend_from_slice(&obj_num.to_le_bytes()[..3]);
    buf.extend_from_slice(&gen_num.to_le_bytes()[..2]);
    let digest = Md5::digest(&buf);
    digest[..(base.len() + 5).min(16)].to_vec()
}

/// Algorithm 2.B — the hash revision 6 (PDF 2.0, AES-256) runs passwords through.
fn hash_r6(password: &[u8], salt: &[u8], udata: &[u8]) -> Vec<u8> {
    let mut k = Sha256::new()
        .chain_update(password)
        .chain_update(salt)
        .chain_update(udata)
        .finalize()
        .to_vec();
    let mut round: i64 = 0;
    loop {
        let unit = [password, &k[..], udata].concat();
        let k1 = unit.repeat(64);
        let e = Aes128CbcEnc::new_from_slices(&k[..16], &k[16..32])
            .expect("16-byte key and IV")
            .encrypt_padded_vec_mut::<NoPadding>(&k1);
        // The first 16 bytes as a big-endian number, mod 3. 256 ≡ 1 (mod 3), so
        // that is the sum of the bytes, mod 3.
        let selector: u32 = e[..16].iter().map(|&b| u32::from(b)).sum::<u32>() % 3;
        k = match selector {
            0 => Sha256::digest(&e).to_vec(),
            1 => Sha384::digest(&e).to_vec(),
            _ => Sha512::digest(&e).to_vec(),
        };
        round += 1;
        if round >= 64 && i64::from(*e.last().expect("non-empty")) <= round - 32 {
            break;
        }
    }
    k.truncate(32);
    k
}

/// Revision 5 (Adobe's deprecated AES-256 extension) hashes once with SHA-256.
fn hash_r5(password: &[u8], salt: &[u8], udata: &[u8]) -> Vec<u8> {
    Sha256::new()
        .chain_update(password)
        .chain_update(salt)
        .chain_update(udata)
        .finalize()
        .to_vec()
}

// ========================== Password Verification ==========================

fn try_user_password(pwd: &[u8], sec: &Security) -> Option<Vec<u8>> {
    let key = compute_encryption_key(
        pwd, &sec.o, sec.permissions, &sec.file_id, sec.key_len, sec.revision, sec.encrypt_metadata,
    );
    let computed = compute_u_value(&key, &sec.file_id, sec.revision);
    let n = if sec.revision >= 3 { 16 } else { 32 };
    if sec.u.len() >= n && computed[..n] == sec.u[..n] { Some(key) } else { None }
}

fn try_owner_password(pwd: &[u8], sec: &Security) -> Option<Vec<u8>> {
    let kl = sec.key_len;
    let padded = pad_password(pwd);
    let mut hash = Md5::digest(padded).to_vec();
    if sec.revision >= 3 {
        for _ in 0..50 {
            hash = Md5::digest(&hash[..kl]).to_vec();
        }
    }
    let rc4_key = &hash[..kl];
    let user_pwd = if sec.revision >= 3 {
        let mut data = sec.o.clone();
        for i in (0..=19u8).rev() {
            let xk: Vec<u8> = rc4_key.iter().map(|b| b ^ i).collect();
            data = rc4(&xk, &data);
        }
        data
    } else {
        rc4(rc4_key, &sec.o)
    };
    try_user_password(&user_pwd, sec)
}

/// Algorithms 2.A / 3.11 / 3.12 — revisions 5 and 6. The password is checked
/// against /U as the user's, then against /O as the owner's, and the file key
/// is unwrapped from /UE or /OE with the matching intermediate key.
fn try_aes256_password(pwd: &[u8], sec: &Security) -> Option<Vec<u8>> {
    // UTF-8, at most 127 bytes (§7.6.4.3.3). SASLprep is not applied, which
    // only matters for passwords with unusual Unicode.
    let pwd = &pwd[..pwd.len().min(127)];
    let hash = |salt: &[u8], udata: &[u8]| {
        if sec.revision == 6 { hash_r6(pwd, salt, udata) } else { hash_r5(pwd, salt, udata) }
    };
    let (o, u) = (&sec.o, &sec.u);
    if o.len() < 48 || u.len() < 48 || sec.oe.len() < 32 || sec.ue.len() < 32 {
        return None;
    }
    if hash(&u[32..40], &[]) == u[..32] {
        return aes256_unwrap(&hash(&u[40..48], &[]), &sec.ue[..32]);
    }
    if hash(&o[32..40], &u[..48]) == o[..32] {
        return aes256_unwrap(&hash(&o[40..48], &u[..48]), &sec.oe[..32]);
    }
    None
}

/// The file key, or None if the password is wrong. The empty password is
/// tried first, so a PDF that opens freely but restricts editing or printing
/// (an owner password only) unlocks without one.
fn find_file_key(sec: &Security, password: &[u8]) -> Option<Vec<u8>> {
    if sec.revision >= 5 {
        try_aes256_password(b"", sec).or_else(|| try_aes256_password(password, sec))
    } else {
        try_user_password(b"", sec)
            .or_else(|| try_user_password(password, sec))
            .or_else(|| try_owner_password(password, sec))
    }
}

// ========================== Object Encryption ==========================

/// RC4 is symmetric — same function for encrypt and decrypt.
/// Recursively processes all strings and stream content in the object tree.
/// Used to protect; unlocking goes through `Decryptor`.
fn crypt_object(obj: &mut Object, key: &[u8]) {
    match obj {
        Object::String(ref mut bytes, _) => {
            *bytes = rc4(key, bytes);
        }
        Object::Stream(ref mut stream) => {
            stream.content = rc4(key, &stream.content);
            for (_, v) in stream.dict.iter_mut() {
                crypt_object(v, key);
            }
        }
        Object::Dictionary(ref mut dict) => {
            for (_, v) in dict.iter_mut() {
                crypt_object(v, key);
            }
        }
        Object::Array(ref mut arr) => {
            for item in arr.iter_mut() {
                crypt_object(item, key);
            }
        }
        _ => {}
    }
}

// ========================== Object Decryption ==========================

/// How a class of data is encrypted: a crypt filter's /CFM (§7.6.5).
#[derive(Clone, Copy, PartialEq, Debug)]
enum Method {
    Identity,
    Rc4,
    Aes128,
    Aes256,
}

/// What the /Encrypt dictionary says, for the standard security handler.
struct Security {
    revision: i64,
    /// File key length in bytes (revisions 2–4).
    key_len: usize,
    o: Vec<u8>,
    u: Vec<u8>,
    oe: Vec<u8>,
    ue: Vec<u8>,
    permissions: i32,
    file_id: Vec<u8>,
    strings: Method,
    streams: Method,
    encrypt_metadata: bool,
}

/// Everything needed to decrypt the objects once the password has checked out.
struct Decryptor {
    key: Vec<u8>,
    strings: Method,
    streams: Method,
    encrypt_metadata: bool,
    /// The /Encrypt dictionary's own object, which is never encrypted.
    encrypt_id: Option<ObjectId>,
    /// Object numbers stored inside object streams. Their container is
    /// decrypted as a whole, so they must not be decrypted a second time.
    compressed: HashSet<u32>,
}

impl Decryptor {
    fn key_for(&self, method: Method, id: ObjectId) -> Vec<u8> {
        match method {
            Method::Identity => Vec::new(),
            Method::Rc4 => object_key(&self.key, id.0, id.1),
            // Algorithm 1, step (b): AESV2 salts the per-object key with "sAlT".
            Method::Aes128 => {
                let mut buf = self.key.clone();
                buf.extend_from_slice(&id.0.to_le_bytes()[..3]);
                buf.extend_from_slice(&id.1.to_le_bytes()[..2]);
                buf.extend_from_slice(b"sAlT");
                Md5::digest(&buf)[..(self.key.len() + 5).min(16)].to_vec()
            }
            // Algorithm 1.A: AES-256 uses the file key for every object.
            Method::Aes256 => self.key.clone(),
        }
    }

    fn decrypt_indirect(&self, id: ObjectId, obj: &mut Object) {
        if Some(id) == self.encrypt_id {
            return;
        }
        let string_key = self.key_for(self.strings, id);
        let stream_key = self.key_for(self.streams, id);
        self.decrypt_value(obj, &string_key, &stream_key);
    }

    fn decrypt_value(&self, obj: &mut Object, string_key: &[u8], stream_key: &[u8]) {
        match obj {
            Object::String(bytes, _) => *bytes = decrypt_bytes(self.strings, string_key, bytes),
            Object::Array(items) => {
                for item in items.iter_mut() {
                    self.decrypt_value(item, string_key, stream_key);
                }
            }
            Object::Dictionary(dict) => {
                for (_, v) in dict.iter_mut() {
                    self.decrypt_value(v, string_key, stream_key);
                }
            }
            Object::Stream(stream) => {
                // Cross-reference streams are never encrypted, dictionary included (§7.6.2).
                if stream.dict.type_is(b"XRef") {
                    return;
                }
                for (_, v) in stream.dict.iter_mut() {
                    self.decrypt_value(v, string_key, stream_key);
                }
                let unencrypted_metadata = !self.encrypt_metadata && stream.dict.type_is(b"Metadata");
                // A stream with its own /Crypt filter names its own crypt filter. In
                // practice that is /Identity, i.e. stored in the clear.
                if unencrypted_metadata || has_crypt_filter(&stream.dict) {
                    return;
                }
                let plain = decrypt_bytes(self.streams, stream_key, &stream.content);
                stream.set_content(plain);
            }
            _ => {}
        }
    }
}

fn decrypt_bytes(method: Method, key: &[u8], data: &[u8]) -> Vec<u8> {
    match method {
        Method::Identity => data.to_vec(),
        Method::Rc4 => rc4(key, data),
        Method::Aes128 | Method::Aes256 => aes_cbc_decrypt(key, data),
    }
}

fn has_crypt_filter(dict: &Dictionary) -> bool {
    match dict.get(b"Filter") {
        Ok(Object::Name(name)) => name == b"Crypt",
        Ok(Object::Array(filters)) => filters.iter().any(|f| matches!(f, Object::Name(n) if n == b"Crypt")),
        _ => false,
    }
}

thread_local! {
    /// The decryptor for the load in progress. lopdf's load filter is a plain
    /// `fn`, not a closure, so this is how it gets the key.
    static LOADING: RefCell<Option<Decryptor>> = const { RefCell::new(None) };
}

/// lopdf's load filter, which runs on every object as it is read and BEFORE
/// lopdf unpacks object streams. That ordering is the point: an encrypted
/// object stream cannot be parsed, so decrypting after a plain load (as this
/// crate used to) silently drops the container and every object in it.
///
/// lopdf 0.34 uses the result differently for the two kinds of object, which
/// is what the two branches mirror:
///  - a top-level object is kept as `obj` after this returns, and the
///    returned value is only checked for `None`;
///  - an object unpacked from an object stream is replaced by the returned
///    value, and is already plaintext, because its container was decrypted.
fn decrypt_on_load(id: ObjectId, obj: &mut Object) -> Option<(ObjectId, Object)> {
    LOADING.with(|cell| {
        let loading = cell.borrow();
        let Some(dec) = loading.as_ref() else {
            return Some((id, obj.clone()));
        };
        if dec.compressed.contains(&id.0) {
            Some((id, std::mem::replace(obj, Object::Null)))
        } else {
            dec.decrypt_indirect(id, obj);
            Some((id, Object::Null))
        }
    })
}

fn load_decrypted(data: &[u8], dec: Decryptor) -> lopdf::Result<Document> {
    LOADING.with(|cell| *cell.borrow_mut() = Some(dec));
    let doc = Reader { buffer: data, document: Document::new() }.read(Some(decrypt_on_load));
    LOADING.with(|cell| *cell.borrow_mut() = None);
    doc
}

// ========================== Helpers ==========================

fn get_existing_file_id(doc: &Document) -> Option<Vec<u8>> {
    doc.trailer
        .get(b"ID").and_then(Object::as_array).ok()
        .and_then(|a| a.first())
        .and_then(|o| o.as_str().ok())
        .filter(|b| !b.is_empty())
        .map(|b| b.to_vec())
}

fn set_file_id(doc: &mut Document, id: &[u8]) {
    doc.trailer.set(
        b"ID".to_vec(),
        Object::Array(vec![
            Object::String(id.to_vec(), StringFormat::Hexadecimal),
            Object::String(id.to_vec(), StringFormat::Hexadecimal),
        ]),
    );
}

fn ensure_file_id(doc: &mut Document, seed: &[u8]) -> Vec<u8> {
    if let Some(id) = get_existing_file_id(doc) {
        return id;
    }
    let id = Md5::digest(seed).to_vec();
    set_file_id(doc, &id);
    id
}

fn crypt_all_objects(doc: &mut Document, enc_key: &[u8], skip_id: Option<ObjectId>) {
    let ids: Vec<ObjectId> = doc.objects.keys().copied().collect();
    for id in ids {
        if Some(id) == skip_id {
            continue;
        }
        let key = object_key(enc_key, id.0, id.1);
        if let Some(obj) = doc.objects.get_mut(&id) {
            crypt_object(obj, &key);
        }
    }
}

fn get_int(dict: &Dictionary, key: &[u8]) -> Option<i64> {
    dict.get(key).ok().and_then(|o| o.as_i64().ok())
}

fn get_bytes(dict: &Dictionary, key: &[u8]) -> Option<Vec<u8>> {
    dict.get(key).ok().and_then(|o| o.as_str().ok()).map(<[u8]>::to_vec)
}

/// The method behind /StmF or /StrF: a crypt filter named in /CF, or /Identity.
fn crypt_filter_method(enc: &Dictionary, which: &[u8]) -> Result<Method, String> {
    let name = enc.get(which).and_then(Object::as_name).unwrap_or(b"Identity");
    if name == b"Identity" {
        return Ok(Method::Identity);
    }
    let cfm = enc
        .get(b"CF").and_then(Object::as_dict)
        .and_then(|cf| cf.get(name)).and_then(Object::as_dict)
        .and_then(|filter| filter.get(b"CFM")).and_then(Object::as_name)
        .unwrap_or(b"None");
    match cfm {
        b"V2" => Ok(Method::Rc4),
        b"AESV2" => Ok(Method::Aes128),
        b"AESV3" => Ok(Method::Aes256),
        b"None" => Ok(Method::Identity),
        other => Err(format!("Unsupported encryption method ({})", String::from_utf8_lossy(other))),
    }
}

/// The /Encrypt dictionary (by reference, as nearly every PDF has it, or
/// inline in the trailer) and the parameters the standard handler needs.
fn read_security(doc: &Document) -> Result<(Security, Option<ObjectId>), String> {
    let (enc, encrypt_id) = match doc.trailer.get(b"Encrypt") {
        Ok(Object::Reference(id)) => (
            doc.get_dictionary(*id).map_err(|_| "Missing /Encrypt dictionary".to_string())?.clone(),
            Some(*id),
        ),
        Ok(Object::Dictionary(dict)) => (dict.clone(), None),
        _ => return Err("This PDF is not password-protected".into()),
    };

    let filter = enc.get(b"Filter").and_then(Object::as_name).unwrap_or(b"Standard");
    if filter != b"Standard" {
        return Err(
            "This PDF is locked to a digital certificate, not a password, so it can't be unlocked with a password"
                .into(),
        );
    }

    let version = get_int(&enc, b"V").unwrap_or(0);
    let revision = get_int(&enc, b"R").ok_or("Missing /R in Encrypt dict")?;

    let (strings, streams, key_len) = match version {
        1 => (Method::Rc4, Method::Rc4, 5),
        2 => {
            let bits = get_int(&enc, b"Length").unwrap_or(40);
            if !(40..=128).contains(&bits) || bits % 8 != 0 {
                return Err("Unsupported encryption key length".into());
            }
            (Method::Rc4, Method::Rc4, (bits / 8) as usize)
        }
        4 => (crypt_filter_method(&enc, b"StrF")?, crypt_filter_method(&enc, b"StmF")?, 16),
        5 => (crypt_filter_method(&enc, b"StrF")?, crypt_filter_method(&enc, b"StmF")?, 32),
        _ => return Err(format!("Unsupported encryption (V={version})")),
    };
    if !(2..=6).contains(&revision) {
        return Err(format!("Unsupported encryption revision (R={revision})"));
    }

    // The file ID feeds the key for revisions 2–4 only.
    let file_id = get_existing_file_id(doc).unwrap_or_default();
    if revision <= 4 && file_id.is_empty() {
        return Err("Missing file /ID".into());
    }

    Ok((
        Security {
            revision,
            key_len,
            o: get_bytes(&enc, b"O").ok_or("Missing /O value")?,
            u: get_bytes(&enc, b"U").ok_or("Missing /U value")?,
            oe: get_bytes(&enc, b"OE").unwrap_or_default(),
            ue: get_bytes(&enc, b"UE").unwrap_or_default(),
            permissions: get_int(&enc, b"P").ok_or("Missing /P value")? as i32,
            file_id,
            strings,
            streams,
            encrypt_metadata: enc.get(b"EncryptMetadata").and_then(Object::as_bool).unwrap_or(true),
        },
        encrypt_id,
    ))
}

// ========================== Core API (no JS dependencies) ==========================

/// Remove the password from a PDF encrypted with the standard security
/// handler: RC4 (40–128 bit), AES-128 or AES-256 (revisions 2–6).
pub fn unlock_pdf_core(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    // Pass 1: the trailer, the /Encrypt dictionary and the cross-reference
    // table. Objects inside encrypted object streams are lost in this pass,
    // which is why nothing else is taken from it.
    let probe = Document::load_mem(data)
        .map_err(|e| format!("Failed to load PDF: {e}"))?;
    if probe.trailer.get(b"Encrypt").is_err() {
        return Err("This PDF is not password-protected".into());
    }
    let (sec, encrypt_id) = read_security(&probe)?;
    let key = find_file_key(&sec, password.as_bytes())
        .ok_or_else(|| "Incorrect password".to_string())?;

    let compressed = probe
        .reference_table
        .entries
        .iter()
        .filter(|(_, entry)| matches!(entry, XrefEntry::Compressed { .. }))
        .map(|(&num, _)| num)
        .collect();

    // Pass 2: the whole document again, decrypting each object as it is read.
    let mut doc = load_decrypted(
        data,
        Decryptor {
            key,
            strings: sec.strings,
            streams: sec.streams,
            encrypt_metadata: sec.encrypt_metadata,
            encrypt_id,
            compressed,
        },
    )
    .map_err(|e| format!("Failed to load PDF: {e}"))?;

    if let Some(id) = encrypt_id {
        doc.objects.remove(&id);
    }
    doc.trailer.remove(b"Encrypt");

    // Object streams are unpacked and the xref is rewritten, so their
    // containers go (lopdf's writer skips them anyway). /Size is then set from
    // what is left: lopdf writes `max_id + 1`, and the original count, which
    // includes the objects removed here, makes `qpdf --check` warn.
    doc.objects.retain(|_, obj| !matches!(obj.type_name(), Ok("ObjStm" | "XRef")));
    doc.max_id = doc.objects.keys().map(|id| id.0).max().unwrap_or(0);

    // Write a classic cross-reference table. The trailer may be an xref
    // stream's dictionary, whose stream-only keys (a /DecodeParms predictor
    // above all) lopdf would otherwise carry into the xref stream it writes.
    doc.reference_table.cross_reference_type = XrefType::CrossReferenceTable;
    for key in [&b"Type"[..], b"W", b"Index", b"Filter", b"DecodeParms", b"Length", b"Prev", b"XRefStm"] {
        doc.trailer.remove(key);
    }

    let mut out = Vec::new();
    doc.save_to(&mut out)
        .map_err(|e| format!("Failed to save PDF: {e}"))?;
    Ok(out)
}

pub fn lock_pdf_core(data: &[u8], user_password: &str, owner_password: &str, id_seed: &[u8]) -> Result<Vec<u8>, String> {
    let mut doc = Document::load_mem(data)
        .map_err(|e| format!("Failed to load PDF: {e}"))?;

    if doc.is_encrypted() {
        return Err("This PDF is already encrypted — unlock it first".into());
    }

    let file_id = ensure_file_id(&mut doc, id_seed);
    let key_len: usize = 16;
    let rev: i64 = 3;
    let permissions: i32 = -4;

    let up = user_password.as_bytes();
    let op = if owner_password.is_empty() { up } else { owner_password.as_bytes() };

    let o_value = compute_o_value(op, up, key_len, rev);
    let enc_key = compute_encryption_key(up, &o_value, permissions, &file_id, key_len, rev, true);
    let u_value = compute_u_value(&enc_key, &file_id, rev);

    let mut edict = Dictionary::new();
    edict.set(b"Filter".to_vec(), Object::Name(b"Standard".to_vec()));
    edict.set(b"V".to_vec(), Object::Integer(2));
    edict.set(b"R".to_vec(), Object::Integer(rev));
    edict.set(b"Length".to_vec(), Object::Integer(128));
    edict.set(b"O".to_vec(), Object::String(o_value, StringFormat::Hexadecimal));
    edict.set(b"U".to_vec(), Object::String(u_value, StringFormat::Hexadecimal));
    edict.set(b"P".to_vec(), Object::Integer(permissions as i64));

    let eid = doc.add_object(Object::Dictionary(edict));
    doc.trailer.set(b"Encrypt".to_vec(), Object::Reference(eid));

    crypt_all_objects(&mut doc, &enc_key, Some(eid));

    let mut out = Vec::new();
    doc.save_to(&mut out)
        .map_err(|e| format!("Failed to save PDF: {e}"))?;
    Ok(out)
}

// ========================== WASM API ==========================

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn unlock_pdf(data: &[u8], password: &str) -> Result<Vec<u8>, JsValue> {
    unlock_pdf_core(data, password).map_err(|e| JsValue::from_str(&e))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn lock_pdf(data: &[u8], user_password: &str, owner_password: &str) -> Result<Vec<u8>, JsValue> {
    let mut seed = Vec::new();
    seed.extend_from_slice(b"pdf-protect-unlock");
    seed.extend_from_slice(&js_sys::Date::now().to_le_bytes());
    seed.extend_from_slice(&js_sys::Math::random().to_le_bytes());
    lock_pdf_core(data, user_password, owner_password, &seed).map_err(|e| JsValue::from_str(&e))
}
