
include std/dll.e
include std/machine.e

ifdef WINDOWS then
atom librhash = open_dll( "librhash.dll" )

elsifdef LINUX then
atom librhash = open_dll({ "librhash.so.0", "librhash.so" })

elsedef
include std/error.e
error:crash( "Platform not supported" )

end ifdef

constant
	_rhash_library_init     = define_c_proc( librhash, "+rhash_library_init", {} ),
	_rhash_msg              = define_c_func( librhash, "+rhash_msg", {C_UINT,C_POINTER,C_SIZE_T,C_POINTER}, C_INT ),
	_rhash_file             = define_c_func( librhash, "+rhash_file", {C_UINT,C_POINTER,C_POINTER}, C_INT ),
	_rhash_init             = define_c_func( librhash, "+rhash_init", {C_UINT}, C_POINTER ),
	_rhash_update           = define_c_func( librhash, "+rhash_update", {C_POINTER,C_POINTER,C_SIZE_T}, C_INT ),
	_rhash_final            = define_c_func( librhash, "+rhash_final", {C_POINTER,C_POINTER}, C_INT ),
	_rhash_reset            = define_c_proc( librhash, "+rhash_reset", {C_POINTER} ),
	_rhash_free             = define_c_proc( librhash, "+rhash_free", {C_POINTER} ),
	_rhash_set_callback     = define_c_proc( librhash, "+rhash_set_callback", {C_POINTER,C_POINTER,C_POINTER} ),
	_rhash_count            = define_c_func( librhash, "+rhash_count", {}, C_INT ),
	_rhash_get_digest_size  = define_c_func( librhash, "+rhash_get_digest_size", {C_UINT}, C_INT ),
	_rhash_get_hash_length  = define_c_func( librhash, "+rhash_get_hash_length", {C_UINT}, C_INT ),
	_rhash_is_base32        = define_c_func( librhash, "+rhash_is_base32", {C_UINT}, C_INT ),
	_rhash_get_name         = define_c_func( librhash, "+rhash_get_name", {C_UINT}, C_POINTER ),
	_rhash_get_magnet_name  = define_c_func( librhash, "+rhash_get_magnet_name", {C_UINT}, C_POINTER ),
	_rhash_print_bytes      = define_c_func( librhash, "+rhash_print_bytes", {C_POINTER,C_POINTER,C_SIZE_T,C_INT}, C_SIZE_T ),
	_rhash_print            = define_c_func( librhash, "+rhash_print", {C_POINTER,C_POINTER,C_UINT,C_INT}, C_SIZE_T ),
	_rhash_print_magnet     = define_c_func( librhash, "+rhash_print_magnet", {C_POINTER,C_POINTER,C_POINTER,C_UINT,C_INT}, C_SIZE_T ),
	_rhash_transmit         = define_c_func( librhash, "+rhash_transmit", {C_UINT,C_POINTER,C_POINTER,C_POINTER}, C_POINTER ),
$

constant BUFFER_SIZE = 256

constant
	rhash_context__msg_size = 0, -- unsigned long long
	rhash_context__hash_id  = 8, -- unsigned
	SIZEOF_RHASH_CONTEXT    = 16,
$

/**
 * Identifiers of supported hash functions.
 * The rhash_init() function allows mixing several ids using
 * binary OR, to calculate several hash functions for one message.
 */
public enum type rhash_ids
	
	RHASH_CRC32            = 0x00000001,
	RHASH_MD4              = 0x00000002,
	RHASH_MD5              = 0x00000004,
	RHASH_SHA1             = 0x00000008,
	RHASH_TIGER            = 0x00000010,
	RHASH_TTH              = 0x00000020,
	RHASH_BTIH             = 0x00000040,
	RHASH_ED2K             = 0x00000080,
	RHASH_AICH             = 0x00000100,
	RHASH_WHIRLPOOL        = 0x00000200,
	RHASH_RIPEMD160        = 0x00000400,
	RHASH_GOST94           = 0x00000800,
	RHASH_GOST94_CRYPTOPRO = 0x00001000,
	RHASH_HAS160           = 0x00002000,
	RHASH_GOST12_256       = 0x00004000,
	RHASH_GOST12_512       = 0x00008000,
	RHASH_SHA224           = 0x00010000,
	RHASH_SHA256           = 0x00020000,
	RHASH_SHA384           = 0x00040000,
	RHASH_SHA512           = 0x00080000,
	RHASH_EDONR256         = 0x00100000,
	RHASH_EDONR512         = 0x00200000,
	RHASH_SHA3_224         = 0x00400000,
	RHASH_SHA3_256         = 0x00800000,
	RHASH_SHA3_384         = 0x01000000,
	RHASH_SHA3_512         = 0x02000000,
	RHASH_CRC32C           = 0x04000000,
	RHASH_SNEFRU128        = 0x08000000,
	RHASH_SNEFRU256        = 0x10000000,
	
	/**
	 * The bit-mask containing all supported hash functions.
	 */
	RHASH_ALL_HASHES       = 0x1FFFFFFF,
	
	RHASH_GOST = RHASH_GOST94, /* deprecated constant name */
	RHASH_GOST_CRYPTOPRO = RHASH_GOST94_CRYPTOPRO, /* deprecated constant name */
	
	/**
	 * The number of supported hash functions.
	 */
	RHASH_HASH_COUNT = 29
	
end type

/**
 * Initialize static data of rhash algorithms
 */
public procedure rhash_library_init()
	c_proc( _rhash_library_init, {} )
end procedure


/* HIGH-LEVEL LIBRHASH INTERFACE */

/**
 * Compute a message digest of the given message.
 *
 * @param hash_id id of message digest to compute
 * @param message the message data to process
 * @param result buffer to receive the binary message digest value
 * @return binary message digest value on success, NULL on error
 */
public function rhash_msg( integer hash_id, sequence message )
	
	-- get the required digest size for this hash_id
	integer size = c_func( _rhash_get_digest_size, {hash_id} )
	
	atom digest = allocate_data( size )
	atom msgptr = allocate_string( message )
	
	object result = NULL
	
	if c_func( _rhash_msg, {hash_id,msgptr,length(message),digest} ) = 0 then
		result = peek({ digest, size })
	end if
	
	free( msgptr )
	free( digest )
	
	return result
end function

/**
 * Compute a single message digest for the given file.
 *
 * @param hash_id id of hash function to compute
 * @param filepath path to the file to process
 * @return binary message digest value on success, NULL on error
 */
public function rhash_file( integer hash_id, sequence filepath )
	
	-- get the required digest size for this hash_id
	integer size = c_func( _rhash_get_digest_size, {hash_id} )
	
	atom digest = allocate_data( size )
	atom fileptr = allocate_string( filepath )
	
	object result = NULL
	
	if c_func( _rhash_file, {hash_id,fileptr,digest} ) = 0 then
		result = peek({ digest, size })
	end if
	
	free( fileptr )
	free( digest )
	
	return result
end function

/* LOW-LEVEL LIBRHASH INTERFACE */

/**
 * Allocate and initialize RHash context for calculating message digests.
 * The context after usage must be freed by calling rhash_free().
 *
 * @param hash_id union of bit-flags, containing ids of hash functions to calculate.
 * @return initialized rhash context, NULL on error and errno is set
 */
public function rhash_init( object hash_id )
	
	-- merge a sequence of hash_ids into one integer value by OR'ing bits
	
	if sequence( hash_id ) then
		
		if length( hash_id ) = 0 then
			return NULL
		end if
		
		for i = 2 to length( hash_id ) do
			hash_id[1] = or_bits( hash_id[1], hash_id[i] )
		end for
		
		hash_id = hash_id[1]
		
	end if
	
	return c_func( _rhash_init, {hash_id} )
end function

/**
 * Calculate message digests of message.
 * Can be called repeatedly with chunks of the message to be hashed.
 *
 * @param ctx the rhash context
 * @param message the message chunk to process
 * @param msglen length of message chunk
 * @return 0 on success; On fail return -1 and set errno
 */
public function rhash_update( atom ctx, sequence message )
	
	atom msgptr = allocate_string( message )
	
	integer result = c_func( _rhash_update, {ctx,msgptr,length(message)} )
	
	free( msgptr )
	
	return result
end function

/**
 * Finalize message digest calculation and return the first message digest.
 *
 * @param ctx the rhash context
 * @return binary message digest value on success, NULL on error
 */
public function rhash_final( atom ctx )
	
	-- find the first available hash_id for this context
	
	atom hash_mask = peek4u( ctx + rhash_context__hash_id )
	atom hash_count = c_func( _rhash_count, {} )
	
	integer hash_id = 0
	
	for i = 1 to hash_count do
		
		integer this_id = power( 2, i )
		
		if and_bits( hash_mask, this_id ) = this_id then
			hash_id = this_id
			exit
		end if
		
	end for
	
	-- get the required digest size for this hash_id
	integer size = c_func( _rhash_get_digest_size, {hash_id} )
	
	atom digest = allocate_data( size )
	
	object result = NULL
	
	if c_func( _rhash_final, {ctx,digest} ) = 0 then
		result = peek({ digest, size })
	end if
	
	free( digest )
	
	return result
end function

/**
 * Re-initialize RHash context to reuse it.
 * Useful to speed up processing of many small messages.
 *
 * @param ctx context to reinitialize
 */
public procedure rhash_reset( atom ctx )
	c_proc( _rhash_reset, {ctx} )
end procedure

/**
 * Free RHash context memory.
 *
 * @param ctx the context to free.
 */
public procedure rhash_free( atom ctx )
	c_proc( _rhash_free, {ctx} )
end procedure

/**
 * Set the callback function to be called from the
 * rhash_file() and rhash_file_update() functions
 * on processing every file block. The file block
 * size is set internally by rhash and now is 8 KiB.
 *
 * @param ctx rhash context
 * @param callback pointer to the callback function
 * @param callback_data pointer to data passed to the callback
 */
public procedure rhash_set_callback( atom ctx, atom callback, atom callback_data = NULL )
	c_proc( _rhash_set_callback, {ctx,callback,callback_data} )
end procedure

/* INFORMATION FUNCTIONS */

/**
 * Returns the number of supported hash algorithms.
 *
 * @return the number of supported hash functions
 */
public function rhash_count()
	return c_func( _rhash_count, {} )
end function

/**
 * Returns the size of binary message digest for given hash function.
 *
 * @param hash_id the id of the hash function
 * @return the size of the message digest in bytes
 */
public function rhash_get_digest_size( integer hash_id )
	return c_func( _rhash_get_digest_size, {hash_id} )
end function

/**
 * Returns the length of message digest string in its default output format.
 *
 * @param hash_id the id of the hash function
 * @return the length of the message digest
 */
public function rhash_get_hash_length( integer hash_id )
	return c_func( _rhash_get_hash_length, {hash_id} )
end function

/**
 * Detect default message digest output format for the given hash algorithm.
 *
 * @param hash_id the id of hash algorithm
 * @return 1 for base32 format, 0 for hexadecimal
 */
public function rhash_is_base32( integer hash_id )
	return c_func( _rhash_is_base32, {hash_id} )
end function

/**
 * Returns the name of the given hash function.
 *
 * @param hash_id id of the hash function
 * @return hash function name
 */
public function rhash_get_name( integer hash_id )
	
	atom ptr = c_func( _rhash_get_name, {hash_id} )
	
	if ptr != NULL then
		return peek_string( ptr )
	end if
	
	return NULL
end function

/**
 * Returns a name part of magnet urn of the given hash algorithm.
 * Such magnet_name is used to generate a magnet link of the form
 * urn:&lt;magnet_name&gt;=&lt;hash_value&gt;.
 *
 * @param hash_id id of the hash algorithm
 * @return name
 */
public function rhash_get_magnet_name( integer hash_id )
	
	atom ptr = c_func( _rhash_get_magnet_name, {hash_id} )
	
	if ptr != NULL then
		return peek_string( ptr )
	end if
	
	return NULL
end function

/* HASH SUM OUTPUT INTERFACE */

/**
 * Flags for printing a message digest.
 */
public enum type rhash_print_sum_flags
	
	/*
	 * Print in a default format
	 */
	RHPR_DEFAULT   = 0x0,
	/*
	 * Output as binary message digest
	 */
	RHPR_RAW       = 0x1,
	/*
	 * Print as a hexadecimal string
	 */
	RHPR_HEX       = 0x2,
	/*
	 * Print as a base32-encoded string
	 */
	RHPR_BASE32    = 0x3,
	/*
	 * Print as a base64-encoded string
	 */
	RHPR_BASE64    = 0x4,
	/*
	 * Print as an uppercase string. Can be used
	 * for base32 or hexadecimal format only.
	 */
	RHPR_UPPERCASE = 0x8,
	/*
	 * Reverse message digest bytes. Can be used for GOST hash functions.
	 */
	RHPR_REVERSE   = 0x10,
	/*
	 * Don't print 'magnet:?' prefix in rhash_print_magnet
	 */
	RHPR_NO_MAGNET  = 0x20,
	/*
	 * Print file size in rhash_print_magnet
	 */
	RHPR_FILESIZE  = 0x40,
	/*
	 * Print as URL-encoded string
	 */
	RHPR_URLENCODE  = 0x80
	
end type

/**
 * Print to the specified buffer the text representation of the given message digest.
 *
 * @param bytes a binary message digest to print
 * @param size a size of the message digest in bytes
 * @param flags  a bit-mask controlling how to format the message digest,
 *               can be a mix of the flags: RHPR_RAW, RHPR_HEX, RHPR_BASE32,
 *               RHPR_BASE64, RHPR_URLENCODE, RHPR_UPPERCASE, RHPR_REVERSE
 * @return the text representation of the message digest, NULL on fail
 */
public function rhash_print_bytes( sequence bytes, integer flags = RHPR_DEFAULT )
	
	atom output = allocate_data( BUFFER_SIZE )
	atom bytesptr = allocate_string( bytes )
	
	object result = NULL
	integer count = c_func( _rhash_print_bytes, {output,bytesptr,length(bytes),flags} )
	
	if count != 0 then
		result = peek({ output, count })
	end if
	
	free( bytesptr )
	free( output )
	
	return result
end function

/**
 * Print to the specified output buffer the text representation of the message digest
 * with the given hash_id. If the hash_id is zero, then print the message digest with
 * the lowest hash_id calculated by the hash context.
 *
 * The function call fails if the context doesn't include the message digest with the
 * given hash_id.
 *
 * @param output a buffer to print the message digest to
 * @param context algorithms state
 * @param hash_id id of the message digest to print or 0 to print the first message
 *                digest saved in the context.
 * @param flags a bitmask controlling how to print the message digest. Can contain
 *              flags RHPR_UPPERCASE, RHPR_HEX, RHPR_BASE32, RHPR_BASE64, etc.
 * @return the text representation of the message digest, NULL on fail
 */
public function rhash_print( atom ctx, integer hash_id = 0, integer flags = RHPR_DEFAULT )
	
	atom output = allocate_data( BUFFER_SIZE )
	
	object result = NULL
	integer count = c_func( _rhash_print, {output,ctx,hash_id,flags} )
	
	if count != 0 then
		result = peek({ output, count })
	end if
	
	free( output )
	
	return result
end function

/**
 * Print magnet link with given filepath and calculated message digest into the
 * output buffer. The hash_mask can limit which message digests will be printed.
 * The function returns the size of the required buffer.
 * If output is NULL the .
 *
 * @param output a string buffer to receive the magnet link or NULL
 * @param filepath the file path to be printed or NULL
 * @param context algorithms state
 * @param hash_mask bit mask of the message digest to add to the link
 * @param flags   can be combination of bits RHPR_UPPERCASE, RHPR_NO_MAGNET,
 *                RHPR_FILESIZE
 * @return magnet link with the given filepath and calculatoed message digest, NULL on fail
 */
public function rhash_print_magnet( atom ctx, sequence filepath, integer hash_mask, integer flags = RHPR_DEFAULT )
	
	atom output = allocate_data( BUFFER_SIZE )
	atom fileptr = allocate_string( filepath )
	
	object result = NULL
	integer count = c_func( _rhash_print_magnet, {output,fileptr,ctx,hash_mask,flags} )
	
	if count != 0 then
		result = peek({ output, count })
	end if
	
	free( fileptr )
	free( output )
	
	return result
end function

/* MESSAGE API */

/**
 * The value returned by rhash_transmit on error.
 */
public constant RHASH_ERROR = (-1)

/**
 * Process a rhash message.
 *
 * @param msg_id message identifier
 * @param dst message destination (can be NULL for generic messages)
 * @param ldata data depending on message
 * @param rdata data depending on message
 * @return message-specific data
 */
public function rhash_transmit( integer msg_id, atom dst, atom ldata, atom rdata )
	return c_func( _rhash_transmit, {msg_id,dst,ldata,rdata} )
end function

/* rhash message constants */

public constant
	RMSG_GET_CONTEXT                =  1,
	RMSG_CANCEL                     =  2,
	RMSG_IS_CANCELED                =  3,
	RMSG_GET_FINALIZED              =  4,
	RMSG_SET_AUTOFINAL              =  5,
	RMSG_SET_OPENSSL_MASK           = 10,
	RMSG_GET_OPENSSL_MASK           = 11,
	RMSG_GET_OPENSSL_SUPPORTED_MASK = 12,
	RMSG_GET_OPENSSL_AVAILABLE_MASK = 13,
	RMSG_GET_LIBRHASH_VERSION       = 14,
$

/* HELPER FUNCTIONS */

/**
 * Get a pointer to the context of the specified hash function.
 */
public function rhash_get_context_ptr( atom ctx, integer hash_id )
	return c_func( _rhash_transmit, {RMSG_GET_CONTEXT,ctx,hash_id,0} )
end function

/**
 * Cancel file processing.
 */
public function rhash_cancel( atom ctx )
	return c_func( _rhash_transmit, {RMSG_CANCEL,ctx,0,0} )
end function

/**
 * Return non-zero if a message digest calculation was canceled, zero otherwise.
 */
public function rhash_is_canceled( atom ctx )
	return c_func( _rhash_transmit, {RMSG_IS_CANCELED,ctx,0,0} )
end function

/**
 * Return non-zero if rhash_final was called for rhash_context.
 */
public function rhash_get_finalized( atom ctx )
	return c_func( _rhash_transmit, {RMSG_GET_FINALIZED,ctx,0,0} )
end function

/**
 * Turn on/off the auto-final flag for the given rhash_context. By default
 * auto-final is on, which means rhash_final is called automatically, if
 * needed when a message digest is retrieved by rhash_print call.
 */
public function rhash_set_autofinal( atom ctx, atom on )
	return c_func( _rhash_transmit, {RMSG_SET_AUTOFINAL,ctx,on,0} )
end function

/**
 * Set the bit-mask of hash algorithms to be calculated by OpenSSL library.
 * The call rhash_set_openssl_mask(0) made before rhash_library_init(),
 * turns off loading of the OpenSSL dynamic library.
 * This call works if the LibRHash was compiled with OpenSSL support.
 */
public function rhash_set_openssl_mask( atom mask )
	return c_func( _rhash_transmit, {RMSG_SET_OPENSSL_MASK,NULL,mask,0} )
end function

/**
 * Return current bit-mask of hash algorithms selected to be calculated by OpenSSL
 * library. Return RHASH_ERROR if LibRHash is compiled without OpenSSL support.
 */
public function rhash_get_openssl_mask()
	return c_func( _rhash_transmit, {RMSG_GET_OPENSSL_MASK,NULL,0,0} )
end function

/**
 * Return the bit-mask of algorithms that can be provided by the OpenSSL plugin,
 * if the library is compiled with OpenSSL support, 0 otherwise. This bit-mask is
 * a constant value computed at compile-time.
 */
public function rhash_get_openssl_supported_mask()
	return c_func( _rhash_transmit, {RMSG_GET_OPENSSL_SUPPORTED_MASK,NULL,0,0} )
end function

/**
 * Return the bit-mask of algorithms that are successfully loaded from
 * OpenSSL library. If the library is not loaded or not supported by LibRHash,
 * then return 0.
 */
public function rhash_get_openssl_available_mask()
	return c_func( _rhash_transmit, {RMSG_GET_OPENSSL_AVAILABLE_MASK,NULL,0,0} )
end function

/**
 * Return librhash version.
 */
public function rhash_get_version()
	return c_func( _rhash_transmit, {RMSG_GET_LIBRHASH_VERSION,NULL,0,0} )
end function

/**
 * Return non-zero if LibRHash has been compiled with OpenSSL support,
 * and zero otherwise.
 */
public function rhash_is_openssl_supported()
	return c_func( _rhash_transmit, {RMSG_GET_OPENSSL_MASK,NULL,0,0} ) != RHASH_ERROR
end function

