//! Relational permutation proof for the certified runtime-type salt selector.
//! This evaluates only permutation arithmetic, never the runtime program value.
use super::lift::{id, Context, V};
use super::model::{Parser, E, S};
use super::SALT;
use crate::decoder::tokenize;

impl Context<'_> {
    pub(super) fn type_salt_block(&mut self, body: &[S]) -> Result<bool, String> {
        let [S::Local(destinations, addresses), S::Local(names, values), rest @ ..] = body else {
            return Ok(false);
        };
        if destinations != &["_sd", "_sr"]
            || names != &["_b"]
            || addresses.len() != 2
            || values.len() != 1
        {
            return Ok(false);
        }
        // The source reads only a plain frame cell through captured standard
        // type. band makes the index a uint14 for every possible type result.
        let E::Call(mask, args) = &values[0] else {
            return Ok(false);
        };
        if !id(mask, "band") || args.len() != 2 || args[1] != E::Int(16383) {
            return Ok(false);
        }
        let E::Bin(add, product, bias) = &args[0] else {
            return Ok(false);
        };
        let E::Bin(mul, length, factor) = product.as_ref() else {
            return Ok(false);
        };
        let E::Unary(len, call) = length.as_ref() else {
            return Ok(false);
        };
        let E::Call(ty, args) = call.as_ref() else {
            return Ok(false);
        };
        let [E::Index(frame, source)] = args.as_slice() else {
            return Ok(false);
        };
        if add != "+"
            || mul != "*"
            || len != "#"
            || !id(ty, "tFn")
            || !id(frame, "F")
            || !id(source, "_sr")
            || !matches!(factor.as_ref(), E::Int(0..=65535))
            || !matches!(bias.as_ref(), E::Int(0..=65535))
        {
            return Ok(false);
        }
        let template = "local _o = lshift(_b,1); local _pa,_pb = band(r16(BL_A,_o),16383),band(r16(BL_B,_o),16383); local _zq = (r16(BL_C,lshift(_pa,1))-(_pb*4+((_b*17+13025)%16384)*2+bxor(bxor(band(rshift(_pa,7),1),band(rshift(_pb,2),1)),1)))%65536";
        let tokens = tokenize(template)?;
        let expected = Parser::new(&tokens, template, 0).block()?;
        if rest.len() != 4 || rest[..3] != expected {
            return Ok(false);
        }
        let S::Assign(targets, values) = &rest[3] else {
            return Ok(false);
        };
        if targets.len() != 1
            || values.len() != 1
            || !matches!(&targets[0],E::Index(t,k)if id(t,"F")&&id(k,"_sd"))
        {
            return Ok(false);
        }
        // Check every uint14 index, including correlation between A/B/C.
        // This is a table identity proof, not an int32/hash-preimage search.
        for index in 0..16384usize {
            let pa = *self
                .initialization
                .permutation_a
                .get(index)
                .ok_or("short permutation A")? as u32
                & 16383;
            let pb = *self
                .initialization
                .permutation_b
                .get(index)
                .ok_or("short permutation B")? as u32
                & 16383;
            let c = *self
                .initialization
                .permutation_c
                .get(pa as usize)
                .ok_or("short permutation C")? as u32;
            let expected = pb * 4
                + ((index as u32 * 17 + 13025) % 16384) * 2
                + (((pa >> 7) & 1) ^ ((pb >> 2) & 1) ^ 1);
            if c.wrapping_sub(expected) & 65535 != SALT {
                return Err("runtime-type permutation salt identity is unproved".to_owned());
            }
        }
        let old = self.locals.clone();
        for (name, address) in destinations.iter().zip(addresses) {
            let value = self.eval(address)?;
            self.locals.insert(name.clone(), value);
        }
        let source = self.locals.get("_sr").ok_or("missing salt source")?.int()?;
        self.program_slot(u16::try_from(source).map_err(|_| "invalid salt source")?)?;
        self.locals.insert("_zq".to_owned(), V::Int(SALT as i64));
        self.statements(&rest[3..])?;
        let changes = self.locals.clone();
        self.locals = old;
        for (name, value) in changes {
            if self.locals.contains_key(&name) {
                self.locals.insert(name, value);
            }
        }
        Ok(true)
    }
}
