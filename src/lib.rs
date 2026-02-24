#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
use lopdf::{Document, Dictionary, Object, ObjectId, StringFormat};
use md5::{Md5, Digest};

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

/// Algorithm 3.2 — compute the file encryption key
fn compute_encryption_key(
    user_pwd: &[u8],
    o_value: &[u8],
    perms: i32,
    file_id: &[u8],
    key_len: usize,
    rev: i64,
) -> Vec<u8> {
    let mut ctx = Md5::new();
    ctx.update(pad_password(user_pwd));
    ctx.update(o_value);
    ctx.update((perms as u32).to_le_bytes());
    ctx.update(file_id);
    if rev >= 4 {
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

// ========================== Password Verification ==========================

fn try_user_password(
    pwd: &[u8], o: &[u8], u: &[u8], p: i32, fid: &[u8], kl: usize, rev: i64,
) -> Option<Vec<u8>> {
    let key = compute_encryption_key(pwd, o, p, fid, kl, rev);
    let computed = compute_u_value(&key, fid, rev);
    let n = if rev >= 3 { 16 } else { 32 };
    if computed[..n] == u[..n] { Some(key) } else { None }
}

fn try_owner_password(
    pwd: &[u8], o: &[u8], u: &[u8], p: i32, fid: &[u8], kl: usize, rev: i64,
) -> Option<Vec<u8>> {
    let padded = pad_password(pwd);
    let mut hash = Md5::digest(padded).to_vec();
    if rev >= 3 {
        for _ in 0..50 {
            hash = Md5::digest(&hash[..kl]).to_vec();
        }
    }
    let rc4_key = &hash[..kl];
    let user_pwd = if rev >= 3 {
        let mut data = o.to_vec();
        for i in (0..=19u8).rev() {
            let xk: Vec<u8> = rc4_key.iter().map(|b| b ^ i).collect();
            data = rc4(&xk, &data);
        }
        data
    } else {
        rc4(rc4_key, o)
    };
    try_user_password(&user_pwd, o, u, p, fid, kl, rev)
}

// ========================== Object Encryption / Decryption ==========================

/// RC4 is symmetric — same function for encrypt and decrypt.
/// Recursively processes all strings and stream content in the object tree.
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

// ========================== Helpers ==========================

struct EncryptParams {
    o_value: Vec<u8>,
    u_value: Vec<u8>,
    permissions: i32,
    file_id: Vec<u8>,
    key_len: usize,
    revision: i64,
}


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

// ========================== Core API (no JS dependencies) ==========================

pub fn unlock_pdf_core(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let mut doc = Document::load_mem(data)
        .map_err(|e| format!("Failed to load PDF: {e}"))?;

    if !doc.is_encrypted() {
        return Err("This PDF is not password-protected".into());
    }

    let params = read_encrypt_params_core(&doc)?;
    let pwd = password.as_bytes();

    let enc_key = try_user_password(b"", &params.o_value, &params.u_value, params.permissions, &params.file_id, params.key_len, params.revision)
        .or_else(|| try_user_password(pwd, &params.o_value, &params.u_value, params.permissions, &params.file_id, params.key_len, params.revision))
        .or_else(|| try_owner_password(pwd, &params.o_value, &params.u_value, params.permissions, &params.file_id, params.key_len, params.revision))
        .ok_or_else(|| "Incorrect password".to_string())?;

    let skip = doc.trailer.get(b"Encrypt").and_then(Object::as_reference).ok();
    crypt_all_objects(&mut doc, &enc_key, skip);
    doc.trailer.remove(b"Encrypt");

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
    let enc_key = compute_encryption_key(up, &o_value, permissions, &file_id, key_len, rev);
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

fn read_encrypt_params_core(doc: &Document) -> Result<EncryptParams, String> {
    let enc = doc
        .get_encrypted()
        .map_err(|_| "Missing /Encrypt dictionary".to_string())?;

    let algo = enc.get(b"V").ok().and_then(|o| o.as_i64().ok()).unwrap_or(0);
    if !(1..=2).contains(&algo) {
        return Err("Unsupported encryption (only V=1/2 RC4 is supported)".into());
    }

    let rev = enc
        .get(b"R").ok()
        .and_then(|o| o.as_i64().ok())
        .ok_or("Missing /R in Encrypt dict")?;
    if !(2..=3).contains(&rev) {
        return Err("Unsupported encryption revision".into());
    }

    let key_len = enc
        .get(b"Length").ok()
        .and_then(|o| o.as_i64().ok())
        .unwrap_or(40) as usize
        / 8;

    let o_value = enc
        .get(b"O").ok()
        .and_then(|o| o.as_str().ok())
        .ok_or("Missing /O value")?
        .to_vec();
    let u_value = enc
        .get(b"U").ok()
        .and_then(|o| o.as_str().ok())
        .ok_or("Missing /U value")?
        .to_vec();
    let permissions = enc
        .get(b"P").ok()
        .and_then(|o| o.as_i64().ok())
        .ok_or("Missing /P value")? as i32;

    let file_id = doc
        .trailer
        .get(b"ID").ok()
        .and_then(|o| o.as_array().ok())
        .and_then(|a| a.first())
        .and_then(|o| o.as_str().ok())
        .ok_or("Missing file /ID")?
        .to_vec();

    Ok(EncryptParams { o_value, u_value, permissions, file_id, key_len, revision: rev })
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
