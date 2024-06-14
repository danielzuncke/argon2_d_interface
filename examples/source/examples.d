module examples;

import argon2;

/+
When using with dub, link like this:

on windows (assuming ./libs/argon2.lib):
"libs": [ "libs/argon2" ] (.lib get appended)

on nix:
(assuming ./libs/libargon2.a)
(must be named lib<name>.a, otherwise linker requires absolute path)
"libs": [ "argon2" ]
"lflags": [ "libs" ]
+/

import std.base64;
import std.conv : to;
import std.digest : LetterCase, toHexString;
import std.stdio : write, writefln, writeln;
import std.string : fromStringz;

int main()
{
	// Examples:
	getErrorMessage();
	writeln("---");

	hashRaw();
	writeln("---");

	hashEndoded();
	writeln("---");

	hashRawAndEncoded();
	writeln("---");

	// This one compares with a test vector, the ones above are arbitrary.
	hashWithCtx();
	return 0;
}

/// Get error message from c style string
void getErrorMessage()
{
	import std.string : fromStringz;

	const errCode = Argon2_ErrorCodes.ARGON2_VERIFY_MISMATCH;
	const(char)* errMsg = argon2_error_message(errCode);
	const s = fromStringz(errMsg);
	writeln("Example error message: ", s);
}

/// Usage of `argon2{d,i,id}_hash_raw(...)`
void hashRaw()
{
	ubyte[16] hash;
	auto t_cost = 2;
	auto m_cost = 32;
	auto parallelism = 1;

	ubyte[4] pwd = 'A';
	ubyte[8] salt = 0;

	auto returnCode = argon2id_hash_raw(t_cost, m_cost, parallelism,
		pwd.ptr, pwd.length,
		salt.ptr, salt.length,
		hash.ptr, hash.length);
	if (returnCode != Argon2_ErrorCodes.ARGON2_OK)
	{
		assert(0, argon2_error_message(returnCode).fromStringz);
	}
	writefln("(Arbitrary) raw hash: %(%02x %)", hash);
}

/// Usage of `argon2{d,i,id}_hash_encoded`
void hashEndoded()
{
	auto t_cost = 4;
	auto m_cost = 1 << 10;
	auto parallelism = 1;

	ubyte[4] pwd = 'A';
	ubyte[8] salt = 0;

	uint hashLength = 32;
	const encodedLength = argon2_encodedlen(t_cost, m_cost, parallelism,
		salt.length, hashLength, Argon2_type.Argon2_id);
	auto encoded = new char[encodedLength];
	/+ Encoded string length depends on hash length and other params, but
		there are no stack arrays of dynamic size.

		Note:
		argon2 has '\0' terminated strings, so appending to the encoded
		string will create this:
		encoded ~= ['A', 'A', 'A']
		=> [ ... , '\0', 'A', 'A', 'A' ]
		This may lead to errors at later points in time.

		Turn encoded into a D style char array by reducing its length by 1 if
		the call was succesful (length check should not be required):
		encoded.length = encoded.length > 0 ? encoded.length - 1 : 0;
		+/

	auto returnCode = argon2id_hash_encoded(
		t_cost, m_cost, parallelism,
		pwd.ptr, pwd.length,
		salt.ptr, salt.length,
		hashLength,
		encoded.ptr, encoded.length);
	if (returnCode != Argon2_ErrorCodes.ARGON2_OK)
	{
		assert(0, argon2_error_message(returnCode).fromStringz);
	}
	// Alternatively use std.string.fromStringz(encoded):
	encoded.length -= 1;
	writefln("(Arbitrary) encoded hash: %s", encoded);
}

/// argon2_hash has both the raw and encoded hash as out params
void hashRawAndEncoded()
{
	ubyte[16] hash;
	auto t_cost = 2;
	auto m_cost = 1 << 10;
	auto parallelism = 1;

	ubyte[4] pwd = 'A';
	ubyte[8] salt = 0;

	const type = Argon2_type.Argon2_id;

	const encodedLength = argon2_encodedlen(t_cost, m_cost, parallelism,
		salt.length, hash.length, type);
	auto encoded = new char[encodedLength];
	/+ Encoded string length depends on hash length and other params, but
		there are no stack arrays of dynamic size.

		Note:
		argon2 has '\0' terminated strings, so appending to the encoded
		string will create this:
		encoded ~= ['A', 'A', 'A']
		=> [ ... , '\0', 'A', 'A', 'A' ]
		This may lead to errors at later points in time.

		Turn encoded into a D style char array by reducing its length by 1 if
		the call was succesful (length check should not be required):
		encoded.length = encoded.length > 0 ? encoded.length - 1 : 0;
		+/

	auto returnCode = argon2_hash(t_cost, m_cost, parallelism,
		pwd.ptr, pwd.length,
		salt.ptr, salt.length,
		hash.ptr, hash.length,
		encoded.ptr, encoded.length,
		type, Argon2_version.ARGON2_VERSION_13);
	if (returnCode != Argon2_ErrorCodes.ARGON2_OK)
	{
		assert(0, argon2_error_message(returnCode).fromStringz);
	}
	// Alternatively call std.string.fromStringz(encoded):
	encoded.length -= 1;
	writeln("(Arbitrary) raw and encoded hash:");
	writefln("Raw bytes: %(%02x %)", hash);
	writefln("Encoded: %s", encoded);
}

void hashWithCtx()
{
	// Values from (note: they call outArr "Tag"):
	// https://www.rfc-editor.org/rfc/rfc9106#name-argon2id-test-vectors
	const ubyte[] result = [
		0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37,
		0xa3, 0x4a, 0x8b, 0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75,
		0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59
	];

	ubyte[32] outArr = 0;
	ubyte[32] password = 1;
	ubyte[16] salt = 2;
	ubyte[8] secret = 3;
	ubyte[12] ad = 4;

	Argon2_Context argon2Ctx;
	argon2Ctx.outArr = outArr.ptr;
	argon2Ctx.outlen = outArr.length;
	argon2Ctx.pwd = password.ptr;
	argon2Ctx.pwdlen = password.length;
	argon2Ctx.salt = salt.ptr;
	argon2Ctx.saltlen = salt.length;
	argon2Ctx.secret = secret.ptr;
	argon2Ctx.secretlen = secret.length;
	argon2Ctx.ad = ad.ptr;
	argon2Ctx.adlen = ad.length;

	argon2Ctx.t_cost = 3;
	argon2Ctx.m_cost = 32; // will be rounded up to KiB (?)
	argon2Ctx.lanes = 4;
	argon2Ctx.threads = ARGON2_MIN_THREADS;

	argon2Ctx.flags = ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET;

	auto returnCode = argon2id_ctx(&argon2Ctx);

	if (returnCode != Argon2_ErrorCodes.ARGON2_OK)
	{
		assert(0, argon2_error_message(returnCode).fromStringz);
	}

	import std.digest : toHexString, LetterCase;

	writeln("Confirming output of a test vector.");
	writefln("Hex string (no spaces): %s",
		toHexString!(LetterCase.lower)(outArr));
	writefln("Base64 string: %s", Base64.encode(outArr));

	assert(outArr == result,
		"outArr does not match result from test vector.");

	foreach (b; password)
	{
		assert(b == 0,
			"Clear password flag was set, but password did not get cleared.");
	}
	foreach (b; secret)
	{
		assert(b == 0,
			"Clear secret flag was set, but secret did not get cleared.");
	}
}
