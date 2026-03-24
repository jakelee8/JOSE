#![cfg(any(feature = "p256", feature = "p384", feature = "p521", feature = "k256"))]

mod k256;
mod p256;
mod p384;
mod p521;
mod sign;
mod verify;

pub use self::k256::*;
pub use self::p256::*;
pub use self::p384::*;
pub use self::p521::*;

use self::sign::*;
use self::verify::*;
use crate::{Algorithm, Signing};

impl<T> From<elliptic_curve::PublicKey<T>> for Algorithm
where
    T: elliptic_curve::CurveArithmetic,
    elliptic_curve::PublicKey<T>: Into<Signing>,
{
    fn from(key: elliptic_curve::PublicKey<T>) -> Self {
        Into::<Signing>::into(key).into()
    }
}

impl<T> From<elliptic_curve::PublicKey<T>> for Signing
where
    T: elliptic_curve::CurveArithmetic,
    for<'a> &'a elliptic_curve::PublicKey<T>: Into<Signing>,
{
    fn from(key: elliptic_curve::PublicKey<T>) -> Self {
        Into::<Signing>::into(key).into()
    }
}

impl<T> From<elliptic_curve::SecretKey<T>> for Algorithm
where
    T: elliptic_curve::CurveArithmetic,
    elliptic_curve::SecretKey<T>: Into<Signing>,
{
    fn from(key: elliptic_curve::SecretKey<T>) -> Self {
        Into::<Signing>::into(key).into()
    }
}

impl<T> From<elliptic_curve::SecretKey<T>> for Signing
where
    T: elliptic_curve::CurveArithmetic,
    for<'a> &'a elliptic_curve::SecretKey<T>: Into<Signing>,
{
    fn from(key: elliptic_curve::SecretKey<T>) -> Self {
        Into::<Signing>::into(key).into()
    }
}
