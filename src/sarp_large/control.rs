//! Source-certified helper algebra. Rotor masks cancel at the caller, and the
//! three-bank register transfer is checked as a bijection before normalization.
use super::lift::{id, Context, Control, Fact, State, V};
use super::model::{E, S};
use super::{slot, word, SALT};
use crate::ir::*;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct HashProof {
    pub subject: Option<u32>,
    pub mask: u32,
    pub extra_seed: u32,
    pub pool_key: u32,
    pub key: u32,
    pub computed: Option<(u32, u32, u32, u32)>,
    pub expected: (u32, u32),
    pub equal: bool,
}

#[derive(Clone, Copy)]
enum Codec {
    A,
    B,
    C,
}
impl Codec {
    fn targets(self) -> [&'static str; 3] {
        match self {
            Self::A => ["_mst", "_mip", "_msh"],
            Self::B => ["_mst", "_msh", "_mip"],
            Self::C => ["_msh", "_mst", "_mip"],
        }
    }
}

impl Context<'_> {
    pub fn validate_transfer_tail(&self) -> Result<(), String> {
        let helper = *self
            .helper_ids
            .last()
            .ok_or("missing helper for transfer-tail proof")?;
        let codec = match helper {
            24 | 7 | 14 | 28 => Codec::A,
            13 | 12 | 29 | 9 => Codec::B,
            31 | 5 | 26 | 17 | 8 => Codec::C,
            _ => return Err("unproved transfer tail helper".to_owned()),
        };
        fn safe(context: &Context<'_>, value: &E) -> bool {
            match value {
                E::Int(_) => true,
                E::Id(name) => [
                    "rb", "ip", "st", "sh", "_r", "_pxs", "_pys", "_u1s", "_u2s", "_mip", "_mst",
                    "_msh", "_sma", "_smb", "_sg", "true", "false",
                ]
                .contains(&name.as_str()),
                E::Bin(_, a, b) => safe(context, a) && safe(context, b),
                E::Call(target, args) => {
                    matches!(target.as_ref(),E::Id(name)if ["bxor","band","bor","lshift","rshift","lrot","rrot","bswap","bext"].contains(&name.as_str()))
                        && args.iter().all(|v| safe(context, v))
                }
                E::Index(table, index) if id(table, "_rm") || id(table, "_rt") => {
                    safe(context, index)
                }
                E::Index(table, index) if id(table, "F") => {
                    if id(index, "_pxs") {
                        return true;
                    }
                    if let E::Index(table, index) = index.as_ref() {
                        if id(table, "_cm") {
                            if let E::Int(index) = index.as_ref() {
                                return usize::try_from(*index)
                                    .ok()
                                    .and_then(|i| i.checked_sub(1))
                                    .and_then(|i| context.family.metadata.get(i))
                                    .is_some_and(|raw| {
                                        slot(context.vm, 21).is_ok_and(|bank| *raw == bank)
                                    });
                            }
                        }
                    }
                    false
                }
                _ => false,
            }
        }
        fn scan(
            context: &Context<'_>,
            body: &[S],
            fields: &mut BTreeMap<String, E>,
        ) -> Result<(), String> {
            for statement in body {
                match statement {
                    S::Do(body) => scan(context, body, fields)?,
                    S::Assign(targets, values) if targets.len() == values.len() => {
                        for (target, value) in targets.iter().zip(values) {
                            let E::Id(name) = target else {
                                return Err("transfer tail writes program/frame data".to_owned());
                            };
                            if ![
                                "rb", "_pxs", "_pys", "_u1s", "_u2s", "_r", "ip", "st", "sh", "_go",
                            ]
                            .contains(&name.as_str())
                                || !safe(context, value)
                            {
                                return Err(format!(
                                    "transfer tail contains unproved effect: {statement:?}"
                                ));
                            }
                            if ["ip", "st", "sh"].contains(&name.as_str())
                                && fields.insert(name.clone(), value.clone()).is_some()
                            {
                                return Err(
                                    "transfer tail writes a decode field more than once".to_owned()
                                );
                            }
                        }
                    }
                    _ => {
                        return Err(format!(
                            "unproved statement after helper return: {statement:?}"
                        ))
                    }
                }
            }
            Ok(())
        }
        let ident = |name: &str| E::Id(name.to_owned());
        let multiply = |factor| {
            E::Bin(
                "*".to_owned(),
                Box::new(ident("_r")),
                Box::new(E::Int(factor)),
            )
        };
        let modulo = |value| {
            E::Bin(
                "%".to_owned(),
                Box::new(value),
                Box::new(E::Int(1i64 << 32)),
            )
        };
        let xor = |name: &str, factor| {
            E::Call(
                Box::new(ident("bxor")),
                vec![ident(name), modulo(multiply(factor))],
            )
        };
        let subtract = |name: &str, factor| {
            modulo(E::Bin(
                "-".to_owned(),
                Box::new(ident(name)),
                Box::new(multiply(factor)),
            ))
        };
        let expected = match codec {
            Codec::A => [
                ("ip", xor("_mip", 29)),
                ("st", subtract("_mst", 61)),
                ("sh", subtract("_msh", 181)),
            ],
            Codec::B => [
                ("ip", subtract("_mip", 23)),
                ("st", xor("_mst", 93)),
                ("sh", subtract("_msh", 125)),
            ],
            Codec::C => [
                ("ip", xor("_mip", 3)),
                ("st", subtract("_mst", 41)),
                ("sh", xor("_msh", 129)),
            ],
        };
        let mut fields = BTreeMap::new();
        scan(self, &self.transfer_tail, &mut fields)?;
        for (name, value) in expected {
            if fields.get(name) != Some(&value) {
                return Err(format!(
                    "helper {helper} caller {name} inverse is not the certified codec"
                ));
            }
        }
        // Prove the whole caller tail, not only inverse-shaped assignments.
        // In particular `_r` cannot be replaced between the helper and codec,
        // and rb/role reloads must match the normalized bank transfer.
        let bank_slot = slot(self.vm, 21)?;
        let bank_index = self
            .family
            .metadata
            .iter()
            .position(|raw| *raw == bank_slot)
            .ok_or("caller metadata lacks current bank slot")?
            + 1;
        let roles = match helper {
            13 | 24 => "_u1s,_u2s,_pxs",
            31 => "_u2s,_pxs,_u1s",
            _ => "_rm[rb+5],_rm[rb+9],_rm[rb+10]",
        };
        let inverses=match codec{
            Codec::A=>"ip=bxor(_mip,(_r*29)%4294967296);st=(_mst-_r*61)%4294967296;sh=(_msh-_r*181)%4294967296",
            Codec::B=>"ip=(_mip-_r*23)%4294967296;st=bxor(_mst,(_r*93)%4294967296);sh=(_msh-_r*125)%4294967296",
            Codec::C=>"ip=bxor(_mip,(_r*3)%4294967296);st=(_mst-_r*41)%4294967296;sh=bxor(_msh,(_r*129)%4294967296)",
        };
        let source=format!("rb=F[_cm[{bank_index}]];_pxs,_u1s,_u2s={roles};_r=bxor(F[_pxs],_sma);{inverses};_go=_rt[sh]==_sg");
        let tokens = crate::decoder::tokenize(&source)?;
        let expected = super::model::Parser::new(&tokens, &source, 0).block()?;
        if self.transfer_tail != expected {
            return Err(format!(
                "helper {helper} full caller transfer tail is not certified"
            ));
        }
        Ok(())
    }
    fn transition(
        &self,
        delta: i64,
        key_delta: i64,
        shape: i64,
        phase: i64,
        forward: bool,
        key_extra: u32,
        shape_extra: u32,
    ) -> Result<State, String> {
        if self.state.window == 0 {
            return Err("transition before rotor/window setup".to_owned());
        }
        let mut next = self.state.clone();
        let target = (self.state.pc as i64)
            .checked_add(delta)
            .ok_or("transition PC overflow")?
            .rem_euclid(1i64 << 32);
        next.pc = usize::try_from(target).map_err(|_| "transition PC conversion")?;
        word(self.vm, next.pc)?;
        next.key = (self.state.key as i64
            + key_delta
            + self.state.phase as i64
            + SALT as i64
            + key_extra as i64)
            .rem_euclid(1i64 << 32) as u32;
        next.token = (shape + self.state.phase as i64 + SALT as i64 + shape_extra as i64)
            .rem_euclid(1i64 << 32) as u32;
        if !self.vm.dispatch_families.contains_key(&next.token) {
            return Err(format!(
                "unmapped shape {} at successor PC {}",
                next.token, next.pc
            ));
        }
        next.phase = phase.rem_euclid(1i64 << 32) as u32;
        let (bank, width, ceiling) = (
            self.state.bank as i64,
            self.state.window as i64,
            self.state.bank_end as i64,
        );
        let next_bank = if forward {
            if bank >= ceiling {
                bank - 2 * width
            } else {
                bank + width
            }
        } else if bank <= ceiling - 2 * width {
            bank + 2 * width
        } else {
            bank - width
        };
        next.bank = u32::try_from(next_bank).map_err(|_| "bank transition overflow")?;
        let read_roles = |bank: usize| -> Result<[u16; 4], String> {
            Ok([
                slot(self.vm, bank + 5)?,
                slot(self.vm, bank + 6)?,
                slot(self.vm, bank + 9)?,
                slot(self.vm, bank + 10)?,
            ])
        };
        let old = read_roles(self.state.bank as usize)?;
        let new = read_roles(next.bank as usize)?;
        let expected = if forward {
            [old[2], old[1], old[3], old[0]]
        } else {
            [old[3], old[1], old[0], old[2]]
        };
        if new != expected {
            return Err(
                "large SARP rotor transfer does not preserve distinct data roles".to_owned(),
            );
        }
        Ok(next)
    }
    pub fn transition_call(&mut self, targets: &[E], values: &[E]) -> Result<bool, String> {
        let [E::Call(function, args)] = values else {
            return Ok(false);
        };
        let E::Index(table, _) = function.as_ref() else {
            return Ok(false);
        };
        if !id(table, "_hc") {
            return Ok(false);
        }
        let helper = self.eval(function)?;
        let V::Helper(helper) = helper else {
            return Err("undefined transition helper".to_owned());
        };
        if helper == 25 {
            return Err("unsupported helper 25 generic iteration: iterator packets, nested dispatcher stop/exit continuations and changing rotor state require an explicit structured-loop IR contract".to_owned());
        }
        if matches!(helper, 18 | 19 | 22 | 27) {
            // These are scalar closure/return helpers, not three-result
            // transitions. They need their own proved source contracts.
            return Ok(false);
        }
        let model = self
            .model
            .helpers
            .get(&helper)
            .ok_or("missing transition helper model")?;
        if model.params.len() != args.len() {
            return Err("transition helper argument count mismatch".to_owned());
        }
        let bound = model
            .params
            .iter()
            .zip(args)
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>();
        for (name, expected) in [
            ("_ip", "ip"),
            ("_rb", "rb"),
            ("_st", "st"),
            ("_F", "F"),
            ("_pxs", "_pxs"),
            ("_pys", "_pys"),
            ("_u1s", "_u1s"),
            ("_u2s", "_u2s"),
        ] {
            if !bound.get(name).is_some_and(|v| id(v, expected)) {
                return Err(format!(
                    "unproved helper {helper} context {name}: {:?}",
                    bound.get(name)
                ));
            }
        }
        for (name, value) in &bound {
            if name.starts_with("_hd") && !matches!(value, E::Int(_)) {
                return Err("unknown/effectful transition filler".to_owned());
            }
        }
        let codec = match helper {
            24 | 7 | 14 | 28 => Codec::A,
            13 | 12 | 29 | 9 => Codec::B,
            31 | 5 | 26 | 17 | 8 => Codec::C,
            _ => return Err(format!("unsupported reachable control helper {helper}")),
        };
        if targets
            .iter()
            .map(|v| if let E::Id(n) = v { n.as_str() } else { "" })
            .collect::<Vec<_>>()
            != codec.targets()
        {
            return Err("helper/caller return codec mismatch".to_owned());
        }
        self.helper_ids.push(helper);
        let arg = |ctx: &mut Self, name: &str| -> Result<V, String> {
            ctx.eval(
                bound
                    .get(name)
                    .ok_or_else(|| format!("missing helper role {name}"))?,
            )
        };
        let number = |ctx: &mut Self, name: &str| -> Result<i64, String> { arg(ctx, name)?.int() };
        if [13, 24, 31].contains(&helper) {
            let delta = number(self, "_d")?;
            let key = number(self, "_ds")?;
            let shape = number(self, "_h")?;
            let phase = number(self, "_ct")?;
            self.control = Some(Control::Next(self.transition(
                delta,
                key,
                shape,
                phase,
                helper != 31,
                0,
                0,
            )?));
            return Ok(true);
        }
        if [8, 9, 28].contains(&helper) {
            let value = arg(self, "_x")?;
            let operand = self.operand(&value)?;
            let subject=match (&value,self.fact(&operand)) {
                (V::Int(v),_)=>Some(i32::try_from(*v).map_err(|_|"hash literal outside int32")?as u32),
                (_,Some(Fact::Integer(v)))=>Some(i32::try_from(v).map_err(|_|"hash fact outside int32")?as u32),
                (V::String(_)|V::Nil|V::Bool(_),_)|(_,Some(Fact::Nil|Fact::Boolean(_)|Fact::NonInt32|Fact::Text(_,_)|Fact::StringLength(_)|Fact::String|Fact::Table|Fact::Function|Fact::BooleanUnknown))=>None,
                _=>return Err("hash gate requires a proved finite int32 or a proved non-int32 type; unknown subject is unsupported".to_owned()),
            };
            let mask = arg(self, "_m32")?;
            let mask = self.u32(&mask)?;
            let extra = arg(self, "_sv")?;
            let extra = self.u32(&extra)?;
            let expected1 = arg(self, "_hp1")?;
            let expected1 = self.u32(&expected1)?;
            let expected2 = arg(self, "_hp2")?;
            let expected2 = self.u32(&expected2)?;
            let result = subject.map(|v| {
                hash_gate(
                    v,
                    mask,
                    extra,
                    self.state.key,
                    self.state.pool_key,
                    &self.initialization.permutation_a,
                    &self.initialization.permutation_b,
                    &self.initialization.permutation_c,
                    &self.vm.immediate_biases,
                )
            });
            let equal = result.is_some_and(|(a, b, _, _)| a == expected1 && b == expected2);
            self.hash_proofs.push(HashProof {
                subject,
                mask,
                extra_seed: extra,
                pool_key: self.state.pool_key,
                key: self.state.key,
                computed: result,
                expected: (expected1, expected2),
                equal,
            });
            let (delta, key, shape, phase, kv_ip, kv_sh) = if equal {
                let (_, _, kv_ip, kv_sh) = result.ok_or("missing proved hash result")?;
                (
                    number(self, "_deq")? + kv_ip as i64,
                    number(self, "_seq")?,
                    number(self, "_heq")?,
                    number(self, "_ceq")? + kv_sh as i64,
                    kv_ip,
                    kv_sh,
                )
            } else {
                (
                    number(self, "_dne")?,
                    number(self, "_sne")?,
                    number(self, "_hne")?,
                    number(self, "_cne")?,
                    0,
                    0,
                )
            };
            let forward = if helper == 9 { !equal } else { equal };
            self.control = Some(Control::Next(self.transition(
                delta,
                key,
                shape,
                phase,
                forward,
                SALT.wrapping_add(kv_ip),
                SALT.wrapping_add(kv_sh),
            )?));
            return Ok(true);
        }
        if helper == 17 {
            // Equality implies identical primitive hashes; tables/userdata use
            // the zero defaults. Therefore _dv=0 on the equality arm without
            // evaluating either value. _z remains the proved permutation salt.
            let left = arg(self, "_x")?;
            let left = self.operand(&left)?;
            let right = arg(self, "_y")?;
            let right = self.operand(&right)?;
            let condition = Condition::Compare {
                op: BinaryOp::Equal,
                left,
                right,
            };
            let d = number(self, "_deq")?;
            let ds = number(self, "_seq")?;
            let h = number(self, "_heq")?;
            let c = number(self, "_ceq")?;
            let yes = self.transition(d, ds, h, c, true, SALT, SALT)?;
            let d = number(self, "_dne")?;
            let ds = number(self, "_sne")?;
            let h = number(self, "_hne")?;
            let c = number(self, "_cne")?;
            let no = self.transition(d, ds, h, c, false, SALT, SALT)?;
            self.control = Some(Control::Branch(condition, yes, no));
            return Ok(true);
        }
        // U(305,c,8620,...,725405) proves _zb=43122 for every supported type.
        let value = arg(self, "_c")?;
        let value = self.operand(&value)?;
        let condition = if let Operand::Expression(e) = &value {
            if let ValueExpression::Binary { op, left, right } = e.as_ref() {
                if matches!(
                    op,
                    BinaryOp::Equal
                        | BinaryOp::NotEqual
                        | BinaryOp::Less
                        | BinaryOp::LessEqual
                        | BinaryOp::Greater
                        | BinaryOp::GreaterEqual
                ) {
                    Condition::Compare {
                        op: *op,
                        left: left.clone(),
                        right: right.clone(),
                    }
                } else {
                    Condition::Truthy(value)
                }
            } else {
                Condition::Truthy(value)
            }
        } else {
            Condition::Truthy(value)
        };
        let delta = number(self, "_dt")?;
        let key = number(self, "_st0")?;
        let shape = number(self, "_ht")?;
        let phase = number(self, "_ct")?;
        let first_forward = matches!(helper, 12 | 14 | 26 | 29);
        let first = self.transition(delta, key, shape, phase, first_forward, SALT, 0)?;
        let delta = number(self, "_df")?;
        let key = number(self, "_sf")?;
        let shape = number(self, "_hf")?;
        let phase = number(self, "_cf")?;
        let second = self.transition(delta, key, shape, phase, !first_forward, SALT, 0)?;
        // BM1[not c]-35==1 selects not c; BM2[not c]-38==1 selects c.
        let first_is_true = matches!(helper, 14 | 26 | 29);
        let (yes, no) = if first_is_true {
            (first, second)
        } else {
            (second, first)
        };
        self.control = Some(Control::Branch(condition, yes, no));
        Ok(true)
    }
}

/// The 320-round constant cipher. This is only called with proved inputs;
/// no int32 preimages are searched and no program expression is invoked.
fn hash_gate(
    value: u32,
    mask: u32,
    extra: u32,
    state: u32,
    pool: u32,
    a: &[u16],
    b: &[u16],
    c: &[u16],
    bias: &[u32],
) -> (u32, u32, u32, u32) {
    let lookup = |table: &[u16], at: u32| table[(at & 16383) as usize] as u32;
    let w0 = value ^ mask ^ pool ^ SALT ^ extra;
    let w1 = w0 ^ (w0 >> 15);
    let a1 = lookup(a, w1);
    let a2 = lookup(b, w1 >> 14);
    let a3 = lookup(c, (w1 >> 18) ^ a1 ^ a2);
    let h1 = w1
        .wrapping_mul(85131)
        .wrapping_add(w0.rotate_left(19))
        .wrapping_add(a1.wrapping_mul(65537))
        .wrapping_add(a2)
        .wrapping_add(state)
        ^ a3.rotate_left(12);
    let t2 = h1 ^ h1.rotate_left(9) ^ mask;
    let b1 = lookup(a, t2);
    let b2 = lookup(b, t2 >> 14);
    let b3 = lookup(c, t2 ^ b1 ^ b2);
    let h2 = t2
        .wrapping_mul(109467)
        .wrapping_add(b1.wrapping_mul(65537))
        .wrapping_add(b2.wrapping_mul(257))
        .wrapping_add(b3)
        .wrapping_add(state)
        ^ h1.rotate_right(19);
    let t3 = h2 ^ h1 ^ w0.rotate_left(12);
    let c1 = lookup(a, t3);
    let c2 = lookup(b, t3 >> 14);
    let c3 = lookup(c, h2 ^ c1 ^ c2);
    let h3 = t3
        .wrapping_mul(121053)
        .wrapping_add(c1.wrapping_mul(65537))
        .wrapping_add(c2.wrapping_mul(257))
        .wrapping_add(c3)
        .wrapping_add(w0.leading_zeros() * 131)
        .wrapping_add(h1.trailing_zeros() * 17)
        ^ h2.swap_bytes();
    let t4 = h3 ^ h2.rotate_left(19) ^ mask;
    let d1 = lookup(a, t4);
    let d2 = lookup(b, t4 >> 14);
    let d3 = lookup(c, h3 ^ d1 ^ d2);
    let (mut hr, mut tr) = (h3, t4);
    let mut scratch = [0u8; 16];
    for (index, value) in [w0, h1, h2, t3].iter().enumerate() {
        scratch[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    for round in 1..=320u32 {
        let offset = (hr & 1) as usize * 8;
        let bits = (tr as f64 + hr as f64 * 0.0009765625 + round as f64).to_bits();
        scratch[offset..offset + 8].copy_from_slice(&bits.to_le_bytes());
        let lo = bits as u32;
        let hi = (bits >> 32) as u32;
        let index = ((tr >> 3) & 7) as usize * 2;
        let i16 = u16::from_le_bytes([scratch[index], scratch[index + 1]]) as u32;
        let kw = bias[1 + ((hr ^ round) & 63) as usize];
        let s1 = lookup(a, tr ^ lo ^ i16);
        let s2 = lookup(b, (tr >> 14) ^ hi);
        let s3 = lookup(c, hr ^ s1 ^ s2 ^ kw);
        let nh = tr
            .wrapping_mul(85131)
            .wrapping_add(hr)
            .wrapping_add(s1.wrapping_mul(65537))
            .wrapping_add(s2.wrapping_mul(257))
            .wrapping_add(s3)
            .wrapping_add(kw)
            .wrapping_add(i16 * 13)
            .wrapping_add(tr.leading_zeros() * 29)
            .wrapping_add(hr.trailing_zeros() * 19)
            .wrapping_add(round * 997)
            ^ hr.rotate_left(12)
            ^ s3.swap_bytes()
            ^ lo;
        tr = nh ^ tr.rotate_right(9) ^ mask ^ state ^ hi;
        let offset = (round & 3) as usize * 4;
        let old = u32::from_le_bytes([
            scratch[offset],
            scratch[offset + 1],
            scratch[offset + 2],
            scratch[offset + 3],
        ]);
        scratch[offset..offset + 4].copy_from_slice(&(old ^ nh).to_le_bytes());
        hr = nh;
    }
    let p1 = hr
        .wrapping_mul(121053)
        .wrapping_add(d1.wrapping_mul(65537))
        .wrapping_add(d3)
        .wrapping_add(mask)
        ^ d2.rotate_left(9)
        ^ h1.rotate_right(12)
        ^ tr;
    let p2 = tr
        .wrapping_mul(85131)
        .wrapping_add(hr)
        .wrapping_add(d2.wrapping_mul(65537))
        .wrapping_add(d1)
        .wrapping_add(state)
        ^ d3.rotate_left(19)
        ^ b3.rotate_right(9)
        ^ h3;
    let ip = (hr ^ d3 ^ c1.rotate_left(13)).wrapping_add(b2.wrapping_mul(65537));
    let sh = (tr ^ d1 ^ c2.rotate_right(11)).wrapping_add(b1.wrapping_mul(65537));
    (p1, p2, ip, sh)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hash320_matches_independent_source_reference_vectors() {
        let vm = crate::decode_source(include_str!("../../tests/fixtures/protected.luau")).unwrap();
        let (_, _, bias, init) =
            super::super::initialize_data(&vm.payload, vm.initialization_argument).unwrap();
        for (input, expected) in [
            (
                (138920, 675590897, 43122, 4225420928, 675551875),
                (2204169260, 2982472156, 3556667885, 583177525),
            ),
            (
                (136924, 1648417297, 608916103, 2784560490, 1648390755),
                (2911021113, 1868075030, 2110936601, 81601156),
            ),
            (
                (0, 675590897, 0, 4225420928, 675551875),
                (1393204744, 4222276010, 3265043314, 3891493306),
            ),
            (
                (1, 1648417297, 1981805674, 2784560490, 1648390755),
                (282847150, 1571344452, 1782690477, 2697319067),
            ),
            (
                (43122, 675590897, 2601618823, 4026385912, 675551875),
                (2603817584, 2991986275, 981933046, 2435227184),
            ),
            (
                (16383, 1648417297, 43122, 2784603416, 1648390755),
                (4122545956, 544180572, 2232344480, 1983702062),
            ),
        ] {
            let (value, mask, extra, key, pool) = input;
            assert_eq!(
                hash_gate(
                    value,
                    mask,
                    extra,
                    key,
                    pool,
                    &init.permutation_a,
                    &init.permutation_b,
                    &init.permutation_c,
                    &bias
                ),
                expected
            );
        }
    }
}
