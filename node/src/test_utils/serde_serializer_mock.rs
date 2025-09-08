// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use serde::ser::{
    SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant,
};
use serde::{Serialize, Serializer};
use serde_json::Error;
use std::cell::RefCell;

#[derive(Default)]
pub struct SerdeSerializerMock {
    serialize_sequence_results: RefCell<Vec<Result<SerializeSeqMock, Error>>>,
}

impl SerdeSerializerMock {
    pub fn serialize_seq_result(self, serializer: Result<SerializeSeqMock, Error>) -> Self {
        self.serialize_sequence_results
            .borrow_mut()
            .push(serializer);
        self
    }
}

#[derive(Default)]
pub struct SerializeSeqMock {
    serialize_element_results: RefCell<Vec<Result<(), Error>>>,
    end_results: RefCell<Vec<Result<(), Error>>>,
}

impl SerializeSeq for SerializeSeqMock {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        self.serialize_element_results.borrow_mut().remove(0)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.end_results.borrow_mut().remove(0)
    }
}

impl SerializeSeqMock {
    pub fn serialize_element_result(self, result: Result<(), Error>) -> Self {
        self.serialize_element_results.borrow_mut().push(result);
        self
    }

    pub fn end_result(self, result: Result<(), Error>) -> Self {
        self.end_results.borrow_mut().push(result);
        self
    }
}

pub struct SerializeTupleMock {}

impl SerializeTuple for SerializeTupleMock {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        unimplemented!("Not yet needed")
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }
}

pub struct SerializeTupleStructMock {}

impl SerializeTupleStruct for SerializeTupleStructMock {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        unimplemented!("Not yet needed")
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }
}

pub struct SerializeTupleVariantMock {}

impl SerializeTupleVariant for SerializeTupleVariantMock {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        unimplemented!("Not yet needed")
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }
}

pub struct SerializeMapMock {}

impl SerializeMap for SerializeMapMock {
    type Ok = ();
    type Error = Error;

    fn serialize_key<T: ?Sized>(&mut self, _key: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        unimplemented!("Not yet needed")
    }

    fn serialize_value<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        unimplemented!("Not yet needed")
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }
}

pub struct SerializeStructMock {}

impl SerializeStruct for SerializeStructMock {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized>(
        &mut self,
        _key: &'static str,
        _value: &T,
    ) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        unimplemented!("Not yet needed")
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }
}

pub struct SerializeStructVariantMock {}

impl SerializeStructVariant for SerializeStructVariantMock {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized>(
        &mut self,
        _key: &'static str,
        _value: &T,
    ) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        unimplemented!("Not yet needed")
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }
}

impl Serializer for SerdeSerializerMock {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = SerializeSeqMock;
    type SerializeTuple = SerializeTupleMock;
    type SerializeTupleStruct = SerializeTupleStructMock;
    type SerializeTupleVariant = SerializeTupleVariantMock;
    type SerializeMap = SerializeMapMock;
    type SerializeStruct = SerializeStructMock;
    type SerializeStructVariant = SerializeStructVariantMock;

    fn serialize_bool(self, _v: bool) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_i8(self, _v: i8) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_i16(self, _v: i16) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_i32(self, _v: i32) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_i64(self, _v: i64) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_u8(self, _v: u8) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_u16(self, _v: u16) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_u32(self, _v: u32) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_u64(self, _v: u64) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_char(self, _v: char) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_str(self, _v: &str) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_bytes(self, _v: &[u8]) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_some<T: ?Sized>(self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        unimplemented!("Not yet needed")
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_newtype_struct<T: ?Sized>(
        self,
        _name: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        unimplemented!("Not yet needed")
    }

    fn serialize_newtype_variant<T: ?Sized>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        unimplemented!("Not yet needed")
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        self.serialize_sequence_results.borrow_mut().remove(0)
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        unimplemented!("Not yet needed")
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        unimplemented!("Not yet needed")
    }
}
