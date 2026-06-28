// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

use secrecy::{ExposeSecret, SecretBox};
use serde_json::{Value, map::Map};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{LithiumError, Result};
use crate::secrets::string::SecretString;

pub struct SecretJson {
    value: Value,
    raw: Option<SecretString>,
}

#[inline]
fn ty_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

impl SecretJson {
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(s)?;
        Ok(Self {
            value: v,
            raw: Some(SecretString::new(s.to_owned())),
        })
    }
    #[inline]
    pub fn from_string(s: String) -> Result<Self> {
        let v: Value = serde_json::from_str(&s)?;
        Ok(Self {
            value: v,
            raw: Some(SecretString::new(s)),
        })
    }
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let s = core::str::from_utf8(bytes)
            .map_err(|e| LithiumError::string_policy().with_source(e))?;
        Self::from_str(s)
    }
    #[inline]
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self> {
        let s =
            String::from_utf8(bytes).map_err(|e| LithiumError::string_policy().with_source(e))?;
        Self::from_string(s)
    }
    #[inline]
    pub fn from_zeroizing_vec(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        let s = core::str::from_utf8(bytes.as_slice())
            .map_err(|e| LithiumError::string_policy().with_source(e))?;
        Self::from_str(s)
    }
    #[inline]
    pub fn from_zeroizing_vec_no_raw(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        let v: Value = serde_json::from_slice(bytes.as_slice())?;
        Ok(Self {
            value: v,
            raw: None,
        })
    }

    fn zeroize_value(v: &mut Value) {
        match v {
            Value::String(s) => {
                s.zeroize();
                s.clear();
                s.shrink_to_fit();
            }
            Value::Array(arr) => {
                for elem in arr.iter_mut() {
                    Self::zeroize_value(elem);
                }
                arr.clear();
                arr.shrink_to_fit();
            }
            Value::Object(map) => {
                let owned: Map<String, Value> = core::mem::take(map);
                for (mut k, mut mut_v) in owned.into_iter() {
                    Self::zeroize_value(&mut mut_v);
                    drop(mut_v);
                    k.zeroize();
                    k.clear();
                    k.shrink_to_fit();
                }
            }
            Value::Number(_) => *v = Value::Null,
            Value::Bool(_) | Value::Null => {}
        }
    }

    #[inline]
    pub fn with_exposed<R>(&self, f: impl FnOnce(&Value) -> R) -> R {
        f(&self.value)
    }
    #[inline]
    pub fn with_exposed_mut<R>(&mut self, f: impl FnOnce(&mut Value) -> R) -> R {
        f(&mut self.value)
    }
    #[inline]
    fn obj(&self) -> Result<&Map<String, Value>> {
        self.value
            .as_object()
            .ok_or_else(LithiumError::json_not_object)
    }
    #[inline]
    fn obj_mut(&mut self) -> Result<&mut Map<String, Value>> {
        self.value
            .as_object_mut()
            .ok_or_else(LithiumError::json_not_object)
    }

    #[inline]
    pub fn get_string(&self, key: &'static str) -> Result<SecretString> {
        let obj = self.obj()?;
        let v = obj
            .get(key)
            .ok_or_else(|| LithiumError::json_missing_field(key))?;
        match v {
            Value::String(s) => Ok(SecretString::new(s.clone())),
            other => Err(LithiumError::json_type_mismatch(key, ty_name(other))),
        }
    }
    #[inline]
    pub fn get_integer(&self, key: &'static str) -> Result<SecretBox<i64>> {
        let obj = self.obj()?;
        let v = obj
            .get(key)
            .ok_or_else(|| LithiumError::json_missing_field(key))?;
        match v.as_i64() {
            Some(i) => Ok(SecretBox::new(Box::new(i))),
            None => Err(LithiumError::json_type_mismatch(key, ty_name(v))),
        }
    }
    #[inline]
    pub fn get_bool(&self, key: &'static str) -> Result<bool> {
        let obj = self.obj()?;
        let v = obj
            .get(key)
            .ok_or_else(|| LithiumError::json_missing_field(key))?;
        v.as_bool()
            .ok_or_else(|| LithiumError::json_type_mismatch(key, ty_name(v)))
    }
    #[inline]
    pub fn get_array(&self, key: &'static str) -> Result<Vec<SecretJson>> {
        let obj = self.obj()?;
        let v = obj
            .get(key)
            .ok_or_else(|| LithiumError::json_missing_field(key))?;
        match v.as_array() {
            Some(a) => Ok(a.iter().cloned().map(SecretJson::from).collect()),
            None => Err(LithiumError::json_type_mismatch(key, ty_name(v))),
        }
    }
    #[inline]
    pub fn get_object(&self, key: &'static str) -> Result<SecretJson> {
        let obj = self.obj()?;
        let v = obj
            .get(key)
            .ok_or_else(|| LithiumError::json_missing_field(key))?;
        match v.as_object() {
            Some(o) => Ok(SecretJson::from(Value::Object(o.clone()))),
            None => Err(LithiumError::json_type_mismatch(key, ty_name(v))),
        }
    }
    #[inline]
    pub fn take_string(&mut self, key: &'static str) -> Result<SecretString> {
        let obj = self.obj_mut()?;
        match obj.remove(key) {
            Some(Value::String(s)) => Ok(SecretString::new(s)),
            Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))),
            None => Err(LithiumError::json_missing_field(key)),
        }
    }
    #[inline]
    pub fn take_bool(&mut self, key: &'static str) -> Result<bool> {
        let obj = self.obj_mut()?;
        match obj.remove(key) {
            Some(Value::Bool(b)) => Ok(b),
            Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))),
            None => Err(LithiumError::json_missing_field(key)),
        }
    }
    #[inline]
    pub fn take_i64(&mut self, key: &'static str) -> Result<SecretBox<i64>> {
        let obj = self.obj_mut()?;
        match obj.remove(key) {
            Some(Value::Number(n)) => n
                .as_i64()
                .map(|i| SecretBox::new(Box::new(i)))
                .ok_or_else(|| LithiumError::json_type_mismatch(key, "number")),
            Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))),
            None => Err(LithiumError::json_missing_field(key)),
        }
    }
    #[inline]
    pub fn take_u64(&mut self, key: &'static str) -> Result<SecretBox<u64>> {
        let obj = self.obj_mut()?;
        match obj.remove(key) {
            Some(Value::Number(n)) => n
                .as_u64()
                .map(|u| SecretBox::new(Box::new(u)))
                .ok_or_else(|| LithiumError::json_type_mismatch(key, "number")),
            Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))),
            None => Err(LithiumError::json_missing_field(key)),
        }
    }
    #[inline]
    pub fn take_f64(&mut self, key: &'static str) -> Result<SecretBox<f64>> {
        let obj = self.obj_mut()?;
        match obj.remove(key) {
            Some(Value::Number(n)) => n
                .as_f64()
                .map(|u| SecretBox::new(Box::new(u)))
                .ok_or_else(|| LithiumError::json_type_mismatch(key, "number")),
            Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))),
            None => Err(LithiumError::json_missing_field(key)),
        }
    }
    #[inline]
    pub fn take_array(&mut self, key: &'static str) -> Result<Vec<SecretJson>> {
        let obj = self.obj_mut()?;
        match obj.remove(key) {
            Some(Value::Array(a)) => Ok(a.into_iter().map(SecretJson::from).collect()),
            Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))),
            None => Err(LithiumError::json_missing_field(key)),
        }
    }
    #[inline]
    pub fn take_object(&mut self, key: &'static str) -> Result<SecretJson> {
        let obj = self.obj_mut()?;
        match obj.remove(key) {
            Some(Value::Object(o)) => Ok(SecretJson::from(Value::Object(o))),
            Some(other) => Err(LithiumError::json_type_mismatch(key, ty_name(&other))),
            None => Err(LithiumError::json_missing_field(key)),
        }
    }
    #[inline]
    pub fn take_raw_json(&mut self) -> Option<SecretString> {
        self.raw.take()
    }
    #[inline]
    pub fn get_raw_json(&self) -> Option<SecretString> {
        self.raw.as_ref().cloned()
    }
}

impl From<Value> for SecretJson {
    fn from(value: Value) -> Self {
        SecretJson { value, raw: None }
    }
}
impl Drop for SecretJson {
    fn drop(&mut self) {
        Self::zeroize_value(&mut self.value);
    }
}
impl fmt::Debug for SecretJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretJson(<redacted>)")
    }
}
impl fmt::Display for SecretJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}
impl ExposeSecret<Value> for SecretJson {
    fn expose_secret(&self) -> &Value {
        &self.value
    }
}
