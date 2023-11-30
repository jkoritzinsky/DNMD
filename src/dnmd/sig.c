#include "internal.h"

bool md_is_field_sig(uint8_t const* sig, size_t sig_len)
{
    if (sig_len == 0)
        return false;

    assert(sig != NULL);
    return (*sig & IMAGE_CEE_CS_CALLCONV_MASK) == IMAGE_CEE_CS_CALLCONV_FIELD;
}

static bool skip_if_sentinel(uint8_t const** sig, size_t* sig_length)
{
    assert(sig != NULL && sig_length != NULL && *sig_length != 0);

    if ((*sig)[0] != ELEMENT_TYPE_SENTINEL)
        return false;

    advance_stream(sig, sig_length, 1);
    return true;
}

// Given a signature buffer, skips over a parameter or return type as defined by the following sections of the ECMA spec:
// II.23.2.10 Param
// II.23.2.11 RetType
// II.23.2.12 Type
static bool skip_sig_element(uint8_t const** sig, size_t* sig_length)
{
    assert(sig != NULL && sig_length != NULL && *sig_length != 0);

    uint8_t elem_type;
    uint32_t ignored_compressed_u32_arg;
    if (!read_u8(sig, sig_length, &elem_type))
    {
        return false;
    }

    assert(elem_type != ELEMENT_TYPE_SENTINEL && "The SENTINEL element should be handled by the caller.");

    switch (elem_type)
    {
        case ELEMENT_TYPE_VOID:
        case ELEMENT_TYPE_BOOLEAN:
        case ELEMENT_TYPE_CHAR:
        case ELEMENT_TYPE_I1:
        case ELEMENT_TYPE_U1:
        case ELEMENT_TYPE_I2:
        case ELEMENT_TYPE_U2:
        case ELEMENT_TYPE_I4:
        case ELEMENT_TYPE_U4:
        case ELEMENT_TYPE_I8:
        case ELEMENT_TYPE_U8:
        case ELEMENT_TYPE_R4:
        case ELEMENT_TYPE_R8:
        case ELEMENT_TYPE_STRING:
        case ELEMENT_TYPE_OBJECT:
        case ELEMENT_TYPE_TYPEDBYREF:
        case ELEMENT_TYPE_I:
        case ELEMENT_TYPE_U:
            return true;
        case ELEMENT_TYPE_FNPTR:
        {
            // We need to read a whole MethodDefSig (II.23.2.1) or MethodRefSig (II.23.2.2) here
            // See II.23.2.12 Type for more details
            uint8_t call_conv;
            if (!read_u8(sig, sig_length, &call_conv))
                return false;

            uint32_t generic_arg_count = 0;
            if ((call_conv & IMAGE_CEE_CS_CALLCONV_GENERIC) == IMAGE_CEE_CS_CALLCONV_GENERIC)
            {
                if (!decompress_u32(sig, sig_length, &generic_arg_count))
                    return false;
            }

            uint32_t param_count;
            if (!decompress_u32(sig, sig_length, &param_count))
                return false;

            // skip return type
            if (!skip_sig_element(sig, sig_length))
                return false;

            // skip parameters
            for (uint32_t i = 0; i < param_count; i++)
            {
                // If we see the SENTINEL element, we'll skip it.
                // As defined in II.23.2.2, the ParamCount field counts the number of
                // Param instances, and SENTINEL is a separate entity in the signature
                // than the Param instances.
                (void)skip_if_sentinel(sig, sig_length);
                if (!skip_sig_element(sig, sig_length))
                    return false;
            }
            return true;
        }
        case ELEMENT_TYPE_PTR:
        case ELEMENT_TYPE_BYREF:
        case ELEMENT_TYPE_SZARRAY:
        case ELEMENT_TYPE_PINNED:
            return skip_sig_element(sig, sig_length);

        case ELEMENT_TYPE_VAR:
        case ELEMENT_TYPE_MVAR:
        case ELEMENT_TYPE_VALUETYPE:
        case ELEMENT_TYPE_CLASS:
            return decompress_u32(sig, sig_length, &ignored_compressed_u32_arg);

        case ELEMENT_TYPE_CMOD_REQD:
        case ELEMENT_TYPE_CMOD_OPT:
            if (!decompress_u32(sig, sig_length, &ignored_compressed_u32_arg))
                return false;
            return skip_sig_element(sig, sig_length);

        case ELEMENT_TYPE_ARRAY:
        {
            // type
            if (!skip_sig_element(sig, sig_length))
                return false;
            // rank
            if (!decompress_u32(sig, sig_length, &ignored_compressed_u32_arg))
                return false;

            uint32_t bound_count;
            if (!decompress_u32(sig, sig_length, &bound_count))
                return false;

            for (uint32_t i = 0; i < bound_count; i++)
            {
                // bound
                if (!decompress_u32(sig, sig_length, &ignored_compressed_u32_arg))
                    return false;
            }

            uint32_t lbound_count;
            if (!decompress_u32(sig, sig_length, &lbound_count))
                return false;

            for (uint32_t i = 0; i < lbound_count; i++)
            {
                int32_t ignored_compressed_i32_arg;
                // lbound
                if (!decompress_i32(sig, sig_length, &ignored_compressed_i32_arg))
                    return false;
            }
            return true;
        }
        case ELEMENT_TYPE_GENERICINST:
        {
            // class or value type
            if (!advance_stream(sig, sig_length, 1))
                return false;

            // token
            if (!decompress_u32(sig, sig_length, &ignored_compressed_u32_arg))
                return false;

            uint32_t num_generic_args;
            if (!decompress_u32(sig, sig_length, &num_generic_args))
                return false;

            for (uint32_t i = 0; i < num_generic_args; ++i)
            {
                if (!skip_sig_element(sig, sig_length))
                    return false;
            }
            return true;
        }
    }
    assert(false && "Unknown element type");
    return false;
}

bool md_create_methoddefsig_from_methodrefsig(uint8_t const* ref_sig, size_t ref_sig_len, uint8_t** def_sig, size_t* def_sig_len)
{
    if (ref_sig_len == 0 || def_sig == NULL || def_sig_len == NULL)
        return false;

    assert(ref_sig != NULL);

    uint8_t const* curr = ref_sig;
    size_t curr_len = ref_sig_len;

    // Consume the calling convention
    uint8_t call_conv;
    if (!read_u8(&curr, &curr_len, &call_conv))
        return false;

    // The MethodDefSig is the same as the MethodRefSig if the calling convention is not vararg.
    // Only in the vararg case does the MethodRefSig have additional data to describe the exact vararg
    // parameter list.
    if ((call_conv & IMAGE_CEE_CS_CALLCONV_MASK) != IMAGE_CEE_CS_CALLCONV_VARARG)
    {
        *def_sig_len = ref_sig_len;
        *def_sig = (uint8_t*)malloc(*def_sig_len);
        if (*def_sig == NULL)
            return false;
        memcpy(*def_sig, ref_sig, *def_sig_len);
        return true;
    }

    // Consume the generic parameter count
    uint32_t generic_param_count = 0;
    if (call_conv & IMAGE_CEE_CS_CALLCONV_GENERIC)
    {
        if (!decompress_u32(&curr, &curr_len, &generic_param_count))
            return false;
    }

    // Consume the parameter count
    uint32_t param_count;
    if (!decompress_u32(&curr, &curr_len, &param_count))
        return false;

    uint8_t const* return_and_parameter_start = curr;
    // Skip return type
    if (!skip_sig_element(&curr, &curr_len))
        return false;

    // Skip parameter types until we see the sentinel
    uint32_t i = 0;
    uint8_t const* def_sig_end = curr;
    for (; i < param_count; i++, def_sig_end = curr)
    {
        if (skip_if_sentinel(&curr, &curr_len))
            break;

        if (!skip_sig_element(&curr, &curr_len))
            return false;
    }

    // Now that we know the number of parameters, we can copy the MethodDefSig portion of the signature
    // and update the parameter count.
    // We need to account for the fact that the parameter count may be encoded with less bytes
    // as it is emitted using the compressed unsigned integer format.
    // A compressed integer is 32 bits in ECMA-335.
    uint8_t encoded_original_param_count[sizeof(uint32_t)];
    size_t encoded_original_param_count_length = ARRAY_SIZE(encoded_original_param_count);
    (void)compress_u32(param_count, encoded_original_param_count, &encoded_original_param_count_length);

    uint8_t encoded_def_param_count[sizeof(uint32_t)];
    size_t encoded_def_param_count_length = ARRAY_SIZE(encoded_def_param_count);
    if (!compress_u32(i, encoded_def_param_count, &encoded_def_param_count_length))
        return false;

    size_t def_sig_buffer_len = (size_t)(def_sig_end - ref_sig) - encoded_original_param_count_length + encoded_def_param_count_length;
    uint8_t* def_sig_buffer = (uint8_t*)malloc(def_sig_buffer_len);
    if (!def_sig_buffer)
        return false;

    // Copy over the signature into the new buffer
    {
        size_t len = def_sig_buffer_len;
        uint8_t* buffer = def_sig_buffer;
        buffer[0] = call_conv;
        (void)advance_stream((uint8_t const**)&buffer, &len, 1);

        if (call_conv & IMAGE_CEE_CS_CALLCONV_GENERIC)
        {
            size_t used_len;
            (void)compress_u32(generic_param_count, buffer, &used_len);
            (void)advance_stream((uint8_t const**)&buffer, &len, used_len);
        }
        memcpy(buffer, encoded_def_param_count, encoded_def_param_count_length);
        (void)advance_stream((uint8_t const**)&buffer, &len, encoded_def_param_count_length);

        // Now that we've re-written the parameter count, we can copy the rest of the signature directly from the MethodRefSig
        memcpy(buffer, return_and_parameter_start, len);
    }

    *def_sig_len = def_sig_buffer_len;
    *def_sig = def_sig_buffer;
    return true;
}

static bool reserve_space(uint8_t** sig_blob, size_t* sig_buffer_size, size_t remaining_space, size_t requested_space)
{
    if (remaining_space >= requested_space) // If we are already big enough, we don't need to expand the buffer.
        return true;
    
    // Scale by 2x or the requested space, whichever is larger.
    size_t new_max_space = max(*sig_buffer_size - remaining_space + requested_space, *sig_buffer_size * 2);
    size_t consumed_space = *sig_buffer_size - requested_space;
    uint8_t* new_sig_blob = realloc(*sig_blob - consumed_space, new_max_space); // We need to realloc from the start of the allocation, so back up from our consumed space to the start.
    if (new_sig_blob == NULL)
        return false;
    
    *sig_blob = new_sig_blob + consumed_space; // Now move back to where we were in the signature buffer to continue writing.
    *sig_buffer_size = new_max_space;
    return true;
}

static bool decode_type_def_or_ref_or_spec_encoded(uint32_t encoded, mdToken* token)
{
    assert(token != NULL);

    uint32_t tag = encoded & 0x3;
    uint32_t row_id = encoded >> 2;

    switch (tag)
    {
        case 0x0:
            *token = CreateTokenType(mdtid_TypeDef) | row_id;
            return true;
        case 0x1:
            *token = CreateTokenType(mdtid_TypeRef) | row_id;
            return true;
        case 0x2:
            *token = CreateTokenType(mdtid_TypeSpec) | row_id;
            return true;
        default:
            return false;
    }
}

// Import a TypeDef (II.23.2.8), TypeRef (II.23.2.9), or TypeSpec (II.23.2.13) token from the source assembly and module into the destination assembly and module.
static bool import_token(
    mdcxt_t* source_assembly_cxt,
    mdcxt_t* source_module_cxt,
    mdcxt_t* destination_assembly_cxt,
    mdcxt_t* destination_module_cxt,
    mdToken* token);

static bool insert_compressed_u32(uint8_t** sig, size_t* sig_length, size_t* sig_buffer_size, uint32_t value)
{
    assert(sig != NULL && sig_length != NULL);

    uint8_t encoded[4];
    size_t encoded_len = 4;
    if (!compress_u32(value, encoded, &encoded_len))
        return false;

    if (!reserve_space(sig, sig_buffer_size, *sig_length, encoded_len))
        return false;

    memcpy(*sig, encoded, encoded_len);
    if (!advance_output_stream(sig, sig_length, encoded_len))
        return false;

    return true;
}

static bool insert_compressed_i32(uint8_t** sig, size_t* sig_length, size_t* sig_buffer_size, int32_t value)
{
    assert(sig != NULL && sig_length != NULL);

    uint8_t encoded[4];
    size_t encoded_len = 4;
    if (!compress_i32(value, encoded, &encoded_len))
        return false;

    if (!reserve_space(sig, sig_buffer_size, *sig_length, encoded_len))
        return false;

    memcpy(*sig, encoded, encoded_len);
    if (!advance_output_stream(sig, sig_length, encoded_len))
        return false;

    return true;
}

// Given a signature buffer, imports any TypeDefOrRefOrSpecEncoded (II.23.2.8) elements in a parameter or return type as defined by the following sections of the ECMA spec and advances the signature buffer:
// II.23.2.10 Param
// II.23.2.11 RetType
// II.23.2.12 Type
static bool import_sig_element(
    mdcxt_t* source_assembly_cxt,
    mdcxt_t* source_module_cxt,
    mdcxt_t* destination_assembly_cxt,
    mdcxt_t* destination_module_cxt,
    uint8_t const** sig,
    size_t* sig_length,
    uint8_t** imported_sig,
    size_t* sig_buffer_size,
    size_t* remaining_imported_sig_length)
{
    assert(sig != NULL && sig_length != NULL && *sig_length != 0 && imported_sig != NULL && remaining_imported_sig_length != NULL && sig_buffer_size != NULL);

    uint8_t elem_type;
    uint32_t encoded_u32_arg;
    uint32_t encoded_token;
    uint32_t token;
    if (!read_u8(sig, sig_length, &elem_type))
    {
        return false;
    }

    if (!reserve_space(imported_sig, sig_buffer_size, *remaining_imported_sig_length, 1)
        || !write_u8(imported_sig, remaining_imported_sig_length, elem_type))
    {
        return false;
    }

    switch (elem_type)
    {
        case ELEMENT_TYPE_VOID:
        case ELEMENT_TYPE_BOOLEAN:
        case ELEMENT_TYPE_CHAR:
        case ELEMENT_TYPE_I1:
        case ELEMENT_TYPE_U1:
        case ELEMENT_TYPE_I2:
        case ELEMENT_TYPE_U2:
        case ELEMENT_TYPE_I4:
        case ELEMENT_TYPE_U4:
        case ELEMENT_TYPE_I8:
        case ELEMENT_TYPE_U8:
        case ELEMENT_TYPE_R4:
        case ELEMENT_TYPE_R8:
        case ELEMENT_TYPE_STRING:
        case ELEMENT_TYPE_OBJECT:
        case ELEMENT_TYPE_TYPEDBYREF:
        case ELEMENT_TYPE_I:
        case ELEMENT_TYPE_U:
        case ELEMENT_TYPE_SENTINEL:
            return true;
        case ELEMENT_TYPE_FNPTR:
        {
            // We need to read a whole MethodDefSig (II.23.2.1) or MethodRefSig (II.23.2.2) here
            // See II.23.2.12 Type for more details
            uint8_t call_conv;
            if (!read_u8(sig, sig_length, &call_conv)
                || !reserve_space(imported_sig, sig_buffer_size, *remaining_imported_sig_length, 1)
                || !write_u8(imported_sig, remaining_imported_sig_length, call_conv))
                return false;

            uint32_t generic_arg_count = 0;
            if ((call_conv & IMAGE_CEE_CS_CALLCONV_GENERIC) == IMAGE_CEE_CS_CALLCONV_GENERIC)
            {
                if (!decompress_u32(sig, sig_length, &generic_arg_count)
                    || !insert_compressed_u32(imported_sig, sig_buffer_size, remaining_imported_sig_length, generic_arg_count))
                    return false;
            }

            uint32_t param_count;
            if (!decompress_u32(sig, sig_length, &param_count)
                || !insert_compressed_u32(imported_sig, sig_buffer_size, remaining_imported_sig_length, generic_arg_count))
                return false;

            // import return type
            if (!import_sig_element(
                source_assembly_cxt,
                source_module_cxt,
                destination_assembly_cxt,
                destination_module_cxt,
                sig,
                sig_length,
                imported_sig,
                sig_buffer_size,
                remaining_imported_sig_length))
                return false;

            // import parameters
            for (uint32_t i = 0; i < param_count; i++)
            {
                // If we see the SENTINEL element, we need to still copy it, but we don't want to treat it as a parameter.
                // As defined in II.23.2.2, the ParamCount field counts the number of
                // Param instances, and SENTINEL is a separate entity in the signature
                // than the Param instances.
                if (skip_if_sentinel(sig, sig_length))
                {
                    if (!reserve_space(imported_sig, sig_buffer_size, *remaining_imported_sig_length, 1)
                        || !write_u8(imported_sig, remaining_imported_sig_length, ELEMENT_TYPE_SENTINEL))
                    {
                        return false;
                    }
                }
                if (!import_sig_element(
                    source_assembly_cxt,
                    source_module_cxt,
                    destination_assembly_cxt,
                    destination_module_cxt,
                    sig,
                    sig_length,
                    imported_sig,
                    sig_buffer_size,
                    remaining_imported_sig_length))
                    return false;
            }
            return true;
        }
        case ELEMENT_TYPE_PTR:
        case ELEMENT_TYPE_BYREF:
        case ELEMENT_TYPE_SZARRAY:
        case ELEMENT_TYPE_PINNED:
            return import_sig_element(
                source_assembly_cxt,
                source_module_cxt,
                destination_assembly_cxt,
                destination_module_cxt,
                sig,
                sig_length,
                imported_sig,
                sig_buffer_size,
                remaining_imported_sig_length);

        case ELEMENT_TYPE_VAR:
        case ELEMENT_TYPE_MVAR:
            return decompress_u32(sig, sig_length, &encoded_u32_arg)
                && insert_compressed_u32(imported_sig, sig_buffer_size, remaining_imported_sig_length, encoded_u32_arg);
        case ELEMENT_TYPE_VALUETYPE:
        case ELEMENT_TYPE_CLASS:
            return decompress_u32(sig, sig_length, &encoded_token)
                && decode_type_def_or_ref_or_spec_encoded(encoded_token, &token)
                && import_token(
                    source_assembly_cxt,
                    source_module_cxt,
                    destination_assembly_cxt,
                    destination_module_cxt,
                    &token)
                && insert_compressed_u32(imported_sig, sig_buffer_size, remaining_imported_sig_length, token);

        case ELEMENT_TYPE_CMOD_REQD:
        case ELEMENT_TYPE_CMOD_OPT:
            return decompress_u32(sig, sig_length, &encoded_token)
                && decode_type_def_or_ref_or_spec_encoded(encoded_token, &token)
                && import_token(
                    source_assembly_cxt,
                    source_module_cxt,
                    destination_assembly_cxt,
                    destination_module_cxt,
                    &token)
                && insert_compressed_u32(imported_sig, sig_buffer_size, remaining_imported_sig_length, token)
                && import_sig_element(
                source_assembly_cxt,
                source_module_cxt,
                destination_assembly_cxt,
                destination_module_cxt,
                sig,
                sig_length,
                imported_sig,
                sig_buffer_size,
                remaining_imported_sig_length);

        case ELEMENT_TYPE_ARRAY:
        {
            // type
            if (!import_sig_element(
                source_assembly_cxt,
                source_module_cxt,
                destination_assembly_cxt,
                destination_module_cxt,
                sig,
                sig_length,
                imported_sig,
                sig_buffer_size,
                remaining_imported_sig_length))
                return false;

            // rank
            if (!decompress_u32(sig, sig_length, &encoded_u32_arg)
                || !insert_compressed_u32(imported_sig, sig_buffer_size, remaining_imported_sig_length, encoded_u32_arg))
                return false;

            uint32_t bound_count;
            if (!decompress_u32(sig, sig_length, &bound_count)
                || !insert_compressed_u32(imported_sig, sig_buffer_size, remaining_imported_sig_length, bound_count))
                return false;

            for (uint32_t i = 0; i < bound_count; i++)
            {
                // bound
                if (!decompress_u32(sig, sig_length, &encoded_u32_arg)
                    || !insert_compressed_u32(imported_sig, sig_buffer_size, remaining_imported_sig_length, encoded_u32_arg))
                    return false;
            }

            uint32_t lbound_count;
            if (!decompress_u32(sig, sig_length, &lbound_count)
                || !insert_compressed_u32(imported_sig, sig_buffer_size, remaining_imported_sig_length, lbound_count))
                return false;

            for (uint32_t i = 0; i < lbound_count; i++)
            {
                int32_t ignored_compressed_i32_arg;
                // lbound
                if (!decompress_i32(sig, sig_length, &ignored_compressed_i32_arg)
                    || !insert_compressed_i32(imported_sig, sig_buffer_size, remaining_imported_sig_length, ignored_compressed_i32_arg))
                    return false;
            }
            return true;
        }
        case ELEMENT_TYPE_GENERICINST:
        {
            // class or value type
            uint8_t class_or_value_type;
            if (!read_u8(sig, sig_length, &class_or_value_type)
                || !reserve_space(imported_sig, sig_buffer_size, *remaining_imported_sig_length, 1)
                || !write_u8(imported_sig, remaining_imported_sig_length, class_or_value_type))
                return false;

            // token
            if (!decompress_u32(sig, sig_length, &encoded_token)
                || !decode_type_def_or_ref_or_spec_encoded(encoded_token, &token)
                || !import_token(
                    source_assembly_cxt,
                    source_module_cxt,
                    destination_assembly_cxt,
                    destination_module_cxt,
                    &token)
                || !insert_compressed_u32(imported_sig, sig_buffer_size, remaining_imported_sig_length, token))
                return false;

            uint32_t num_generic_args;
            if (!decompress_u32(sig, sig_length, &num_generic_args)
                || !insert_compressed_u32(imported_sig, sig_buffer_size, remaining_imported_sig_length, num_generic_args))
                return false;

            for (uint32_t i = 0; i < num_generic_args; ++i)
            {
                if (!import_sig_element(
                    source_assembly_cxt,
                    source_module_cxt,
                    destination_assembly_cxt,
                    destination_module_cxt,
                    sig,
                    sig_length,
                    imported_sig,
                    sig_buffer_size,
                    remaining_imported_sig_length))
                    return false;
            }
            return true;
        }
    }
    assert(false && "Unknown element type");
    return false;
}

typedef struct nested_type_chain__
{
    mdcursor_t type;
    struct nested_type_chain__* nested_type;
} nested_type_chain_t;

static nested_type_chain_t* add_enclosing_type_to_chain(nested_type_chain_t* chain, mdcursor_t type)
{
    nested_type_chain_t* new_chain = malloc(sizeof(nested_type_chain_t));
    if (new_chain == NULL)
        return NULL;
    
    new_chain->type = type;
    new_chain->nested_type = chain;
    return new_chain;
}

static void free_nested_type_chain(nested_type_chain_t* chain)
{
    if (chain == NULL)
        return;
    
    free_nested_type_chain(chain->nested_type);
    free(chain);
}

bool get_mvid(mdcxt_t* cxt, mdguid_t* mvid)
{
    assert(mvid != NULL);
    mdcursor_t c;
    uint32_t count;
    if (!md_create_cursor(cxt, mdtid_Module, &c, &count))
        return false;

    return 1 != md_get_column_value_as_guid(c, mdtModule_Mvid, 1, mvid);
}

static bool import_typedef(
    mdcxt_t* source_assembly_cxt,
    mdcxt_t* source_module_cxt,
    mdcxt_t* destination_assembly_cxt,
    mdcxt_t* destination_module_cxt,
    uint8_t const* source_assembly_hash,
    uint32_t source_assembly_hash_length,
    bool resolve_existing_token,
    mdToken* token
)
{
    mdguid_t destination_module_mvid;
    mdguid_t destination_assembly_mvid;
    mdguid_t source_assembly_mvid;
    mdguid_t source_module_mvid;
    if (!get_mvid(destination_module_cxt, &destination_module_mvid))
        return false;
    if (!get_mvid(destination_assembly_cxt, &destination_assembly_mvid))
        return false;
    if (!get_mvid(source_assembly_cxt, &source_assembly_mvid))
        return false;
    if (!get_mvid(source_module_cxt, &source_module_mvid))
        return false;

    bool same_module_mvid = memcmp(&destination_module_mvid, &source_module_mvid, sizeof(mdguid_t)) == 0;
    bool same_assembly_mvid = memcmp(&destination_assembly_mvid, &source_assembly_mvid, sizeof(mdguid_t)) == 0;

    mdcursor_t resolution_scope;
    if (same_assembly_mvid && same_module_mvid)
    {
        // If we should resolve an existing token to itself, then we're done here.
        if (resolve_existing_token)
            return true;

        uint32_t count;
        if (!md_create_cursor(destination_module_cxt, mdtid_Module, &resolution_scope, &count))
            return false;
    }
    else if (same_assembly_mvid && !same_module_mvid)
    {
        char const* import_name;
        mdcursor_t import_module;
        uint32_t count;
        if (!md_create_cursor(source_module_cxt, mdtid_Module, &import_module, &count)
            || 1 != md_get_column_value_as_utf8(import_module, mdtModule_Name, 1, &import_name))
        {
            return false;
        }

        mdcursor_t module_ref;
        if (!md_append_row(destination_module_cxt, mdtid_ModuleRef, &module_ref))
        {
            return false;
        }

        md_commit_row_add(module_ref);

        if (1 != md_set_column_value_as_utf8(module_ref, mdtModuleRef_Name, 1, &import_name))
        {
            return false;
        }

        resolution_scope = module_ref;
    }
    else if (same_module_mvid)
    {
        // The import can't be the same module and different assemblies.
        return false;
    }
    else
    {
        // TODO: Create assembly ref
        mdcursor_t source_assembly;
        uint32_t count;
        if (!md_create_cursor(source_module_cxt, mdtid_Assembly, &source_assembly, &count))
            return false;
        
        uint32_t flags;
        if (1 != md_get_column_value_as_constant(source_assembly, mdtAssembly_Flags, 1, &flags))
            return false;

        uint8_t const* public_key;
        uint32_t public_key_length;
        if (1 != md_get_column_value_as_blob(source_assembly, mdtAssembly_PublicKey, 1, &public_key, &public_key_length))
            return false;
        
        if (public_key != NULL)
        {
            assert(IsAfPublicKey(flags));
            flags &= ~afPublicKey;
            // TODO: Generate token from public key.
        }
        else
        {
            assert(!IsAfPublicKey(flags));
        }

        mdcursor_t assembly_ref;
        if (!md_append_row(destination_module_cxt, mdtid_AssemblyRef, &assembly_ref))
            return false;
        
        md_commit_row_add(assembly_ref);

        uint32_t temp;
        if (1 != md_get_column_value_as_constant(source_assembly, mdtAssembly_MajorVersion, 1, &temp)
            || 1 != md_set_column_value_as_constant(assembly_ref, mdtAssemblyRef_MajorVersion, 1, &temp))
        {
            return false;
        }

        if (1 != md_get_column_value_as_constant(source_assembly, mdtAssembly_MinorVersion, 1, &temp)
            || 1 != md_set_column_value_as_constant(assembly_ref, mdtAssemblyRef_MinorVersion, 1, &temp))
        {
            return false;
        }

        if (1 != md_get_column_value_as_constant(source_assembly, mdtAssembly_BuildNumber, 1, &temp)
            || 1 != md_set_column_value_as_constant(assembly_ref, mdtAssemblyRef_BuildNumber, 1, &temp))
        {
            return false;
        }

        if (1 != md_get_column_value_as_constant(source_assembly, mdtAssembly_RevisionNumber, 1, &temp)
            || 1 != md_set_column_value_as_constant(assembly_ref, mdtAssemblyRef_RevisionNumber, 1, &temp))
        {
            return false;
        }
        
        // TODO: Public Key/Token and Flags
        if (1 != md_set_column_value_as_constant(assembly_ref, mdtAssemblyRef_Flags, 1, &flags))
            return false;
        
        char const* assemblyName;
        if (1 != md_get_column_value_as_utf8(source_assembly, mdtAssembly_Name, 1, &assemblyName)
            || 1 != md_set_column_value_as_utf8(assembly_ref, mdtAssemblyRef_Name, 1, &assemblyName))
        {
            return false;
        }

        char const* assemblyCulture;
        if (1 != md_get_column_value_as_utf8(source_assembly, mdtAssembly_Culture, 1, &assemblyCulture)
            || 1 != md_set_column_value_as_utf8(assembly_ref, mdtAssemblyRef_Culture, 1, &assemblyCulture))
        {
            return false;
        }

        if (1 != md_set_column_value_as_blob(assembly_ref, mdtAssemblyRef_HashValue, 1, &source_assembly_hash, &source_assembly_hash_length))
            return false;
        
        resolution_scope = assembly_ref;
    }

    nested_type_chain_t* nested_type_chain = NULL;

    mdcursor_t importType;
    if (!md_token_to_cursor(source_module_cxt, tdImport, &importType))
        return false;
    
    nested_type_chain = add_enclosing_type_to_chain(&nested_type_chain, importType);
    
    mdcursor_t nestedClasses;
    uint32_t nestedClassCount;
    if (!md_create_cursor(source_module_cxt, mdtid_NestedClass, &nestedClasses, &nestedClassCount))
    {
        free_nested_type_chain(nested_type_chain);
        return false;
    }
    
    mdToken nestedTypeToken = tdImport;
    mdcursor_t nestedClass;
    while (md_find_row_from_cursor(nestedClasses, mdtNestedClass_NestedClass, RidFromToken(nestedTypeToken), &nestedClass))
    {
        mdcursor_t enclosingClass;
        if (1 != md_get_column_value_as_cursor(nestedClass, mdtNestedClass_EnclosingClass, 1, &enclosingClass))
        {
            free_nested_type_chain(nested_type_chain);
            return false;
        }
        
        nested_type_chain = add_enclosing_type_to_chain(&nested_type_chain, enclosingClass);
        if (!md_cursor_to_token(enclosingClass, &nestedTypeToken))
        {
            free_nested_type_chain(nested_type_chain);
            return false;
        }
    }

    for (nested_type_chain_t* current_type = nested_type_chain; current_type != NULL; current_type = current_type->nested_type)
    {
        mdcursor_t type_def = current_type->type;
        mdcursor_t type_ref;
        if (!md_append_row(destination_module_cxt, mdtid_TypeRef, &type_ref))
        {
            free_nested_type_chain(nested_type_chain);
            return false;
        }
        
        md_commit_row_add(type_ref);
        
        if (1 != md_set_column_value_as_cursor(type_ref, mdtTypeRef_ResolutionScope, 1, &resolution_scope))
        {
            free_nested_type_chain(nested_type_chain);
            return false;
        }
        
        char const* type_name;
        if (1 != md_get_column_value_as_utf8(type_def, mdtTypeDef_TypeName, 1, &type_name)
            || 1 != md_set_column_value_as_utf8(type_ref, mdtTypeRef_TypeName, 1, &type_name))
        {
            free_nested_type_chain(nested_type_chain);
            return false;
        }
        
        char const* type_namespace;
        if (1 != md_get_column_value_as_utf8(type_def, mdtTypeDef_TypeNamespace, 1, &type_namespace)
            || 1 != md_set_column_value_as_utf8(type_ref, mdtTypeRef_TypeNamespace, 1, &type_namespace))
        {
            free_nested_type_chain(nested_type_chain);
            return false;
        }

        resolution_scope = type_ref;
    }

    free_nested_type_chain(nested_type_chain);
    return md_cursor_to_token(resolution_scope, token);
}

static bool import_typespec(
    mdcxt_t* source_assembly_cxt,
    mdcxt_t* source_module_cxt,
    mdcxt_t* destination_assembly_cxt,
    mdcxt_t* destination_module_cxt,
    mdTypeSpec* token)
{
    // Import the signature of the TypeSpec from the source module and assembly into the destination module and assembly.
    mdcursor_t source_typespec;
    if (!md_token_to_cursor(source_module_cxt, *token, &source_typespec))
        return false;
    uint8_t const* type_spec_sig;
    uint32_t type_spec_sig_len;
    if (1 != md_get_column_value_as_blob(source_typespec, mdtTypeSpec_Signature, 1, &type_spec_sig, &type_spec_sig_len))
        return false;
    
    size_t imported_type_spec_sig_buffer_len = type_spec_sig_len;
    uint8_t* imported_type_spec_sig = malloc(imported_type_spec_sig_buffer_len);
    if (imported_type_spec_sig == NULL)
        return false;
    
    size_t remaining_imported_type_spec_sig_length = type_spec_sig_len;
    if (!import_sig_element(
        source_assembly_cxt,
        source_module_cxt,
        destination_assembly_cxt,
        destination_module_cxt,
        &type_spec_sig,
        &imported_type_spec_sig_buffer_len,
        &imported_type_spec_sig,
        &imported_type_spec_sig_buffer_len,
        &remaining_imported_type_spec_sig_length))
    {
        free(imported_type_spec_sig);
        return false;
    }
    
    uint32_t imported_type_spec_sig_len = (uint32_t)(imported_type_spec_sig_buffer_len - remaining_imported_type_spec_sig_length);
    imported_type_spec_sig = imported_type_spec_sig - imported_type_spec_sig_len; // Move back to the start of the buffer.

    // Check if a TypeSpec with the same signature already exists in the destination module.
    mdcursor_t destination_typespec;
    uint32_t count;
    if (!md_create_cursor(destination_module_cxt, mdtid_TypeSpec, &destination_typespec, &count))
    {
        free(imported_type_spec_sig);
        return false;
    }

    bool found = false;
    for (uint32_t i = 0; i < count; ++i, md_cursor_next(&destination_typespec))
    {
        uint8_t const* destination_type_spec_sig;
        uint32_t destination_type_spec_sig_len;
        if (1 != md_get_column_value_as_blob(destination_typespec, mdtTypeSpec_Signature, 1, &destination_type_spec_sig, &destination_type_spec_sig_len))
        {
            free(imported_type_spec_sig);
            return false;
        }

        if (destination_type_spec_sig_len == imported_type_spec_sig_len && memcmp(destination_type_spec_sig, imported_type_spec_sig, destination_type_spec_sig_len) == 0)
        {
            found = true;
            break;
        }
    }

    if (found)
    {
        // If we found the TypeSpec, we can just use the existing token.
        free(imported_type_spec_sig);
        return md_cursor_to_token(destination_typespec, token);
    }
    
    // If we didn't find the TypeSpec, we need to create a new one.
    mdcursor_t new_typespec;
    if (!md_append_row(destination_module_cxt, mdtid_TypeSpec, &new_typespec))
    {
        free(imported_type_spec_sig);
        return false;
    }
    
    // The TypeSpec table is unsorted, so we can commit the row-add here.
    md_commit_row_add(new_typespec);

    // Set the signature of the new TypeSpec.
    if (!md_set_column_value_as_blob(new_typespec, mdtTypeSpec_Signature, 1, &imported_type_spec_sig, &imported_type_spec_sig_len))
    {
        free(imported_type_spec_sig);
        return false;
    }

    // Now that we've set the column value, we can free our signature buffer.
    free(imported_type_spec_sig);

    // Update the token to the new TypeSpec token.
    return md_cursor_to_token(new_typespec, token);
}

static bool import_token(
    mdcxt_t* source_assembly_cxt,
    mdcxt_t* source_module_cxt,
    mdcxt_t* destination_assembly_cxt,
    mdcxt_t* destination_module_cxt,
    mdToken* token)
{
    switch (ExtractTokenType(*token))
    {
        case mdtid_TypeDef:
            return import_typedef(
                source_assembly_cxt,
                source_module_cxt,
                destination_assembly_cxt,
                destination_module_cxt,
                true,
                token);
        case mdtid_TypeRef:
            // TODO: Implement TypeRef import
            break;
        case mdtid_TypeSpec:
            return import_typespec(
                source_assembly_cxt,
                source_module_cxt,
                destination_assembly_cxt,
                destination_module_cxt,
                token);
        default:
            assert(false && "Unknown token type");
            return false;
    }

    return false;
}

bool md_import_typedef(
    mdhandle_t source_assembly,
    mdhandle_t source_module,
    mdhandle_t destination_assembly,
    mdhandle_t destination_module,
    uint8_t const* source_assembly_hash,
    uint32_t source_assembly_hash_length,
    mdToken* token)
{
    if (token == NULL || source_assembly_hash == NULL)
        return false;

    if (ExtractTokenType(*token) != mdtid_TypeDef)
        return false;
    
    mdcxt_t* source_assembly_cxt = extract_mdcxt(source_assembly);
    if (source_assembly_cxt == NULL)
        return false;

    mdcxt_t* source_module_cxt = extract_mdcxt(source_module);
    if (source_module_cxt == NULL)
        return false;

    mdcxt_t* destination_assembly_cxt = extract_mdcxt(destination_assembly);
    if (destination_assembly_cxt == NULL)
        return false;

    mdcxt_t* destination_module_cxt = extract_mdcxt(destination_module);
    if (destination_module_cxt == NULL)
        return false;

    return import_typedef(
        source_assembly_cxt,
        source_module_cxt,
        destination_assembly_cxt,
        destination_module_cxt,
        false,
        token);
}

bool md_import_signature(mdhandle_t source_assembly, mdhandle_t source_module, mdhandle_t destination_assembly, mdhandle_t destination_module, uint8_t const* sig, size_t sig_len, uint8_t** imported_sig, size_t* imported_sig_len)
{
    if (sig == NULL || sig_len == 0 || imported_sig == NULL || imported_sig_len == NULL)
        return false;
    
    mdcxt_t* source_assembly_cxt = extract_mdcxt(source_assembly);
    if (source_assembly_cxt == NULL)
        return false;

    mdcxt_t* source_module_cxt = extract_mdcxt(source_module);
    if (source_module_cxt == NULL)
        return false;

    mdcxt_t* destination_assembly_cxt = extract_mdcxt(destination_assembly);
    if (destination_assembly_cxt == NULL)
        return false;

    mdcxt_t* destination_module_cxt = extract_mdcxt(destination_module);
    if (destination_module_cxt == NULL)
        return false;

    // TODO: If the source and destination assemblies are the same, we can skip the assembly import. (Can we do this based on assembly identity?)
    // TODO: If the source and destination module MVIDs are the same and the assemblies are the same, we can just copy the signature.

    // Start with a signature buffer of the same length as the existing signature.
    uint8_t* imported_sig_buffer = malloc(sig_len);
    if (imported_sig_buffer == NULL)
        return false;
    
    size_t imported_sig_buffer_size = sig_len;
    size_t remaining_imported_sig_length = sig_len;

    uint8_t call_conv;
    if (!read_u8(&sig, &sig_len, &call_conv)
        || !reserve_space(&imported_sig_buffer, &imported_sig_buffer_size, remaining_imported_sig_length, 1)
        || !write_u8(&imported_sig_buffer, &remaining_imported_sig_length, call_conv))
    {
        free(imported_sig_buffer);
        return false;
    }

    switch (call_conv & IMAGE_CEE_CS_CALLCONV_MASK)
    {
        // If we have a FieldSig, we only need to import the CustomMod and Type elements, which a single call to import_sig_element handles.
        case IMAGE_CEE_CS_CALLCONV_FIELD:  
        if (!import_sig_element(
            source_assembly_cxt,
            source_module_cxt,
            destination_assembly_cxt,
            destination_module_cxt,
            &sig,
            &sig_len,
            &imported_sig_buffer,
            &imported_sig_buffer_size,
            &remaining_imported_sig_length))
        {
            free(imported_sig_buffer);
            return false;
        }
        break;
        // LocalSig and MethodSpecSig both have a count and a sequence of N elements that can be parsed by a call to import_sig_element.
        case IMAGE_CEE_CS_CALLCONV_LOCAL_SIG:
        case IMAGE_CEE_CS_CALLCONV_GENERICINST:
        {
            uint32_t element_count;
            if (!decompress_u32(&sig, &sig_len, &element_count)
                || !insert_compressed_u32(&imported_sig_buffer, &imported_sig_buffer_size, &remaining_imported_sig_length, element_count))
            {
                free(imported_sig_buffer);
                return false;
            }

            for (uint32_t i = 0; i < element_count; i++)
            {
                if (!import_sig_element(
                    source_assembly_cxt,
                    source_module_cxt,
                    destination_assembly_cxt,
                    destination_module_cxt,
                    &sig,
                    &sig_len,
                    &imported_sig_buffer,
                    &imported_sig_buffer_size,
                    &remaining_imported_sig_length))
                {
                    free(imported_sig_buffer);
                    return false;
                }
            }
        }
        break;
        // PropertySig, MethodDefSig, and MethodRefSig all have a count, a ReturnType or a subset thereof, and a sequence of N parameters that can be parsed by a call to import_sig_element.
        case IMAGE_CEE_CS_CALLCONV_PROPERTY:
        default:
        {
            uint32_t element_count;
            if (!decompress_u32(&sig, &sig_len, &element_count)
                || !insert_compressed_u32(&imported_sig_buffer, &imported_sig_buffer_size, &remaining_imported_sig_length, element_count))
            {
                free(imported_sig_buffer);
                return false;
            }

            // Parse an extra element for the return type.
            for (uint32_t i = 0; i < element_count + 1; i++)
            {
                if (!import_sig_element(
                    source_assembly_cxt,
                    source_module_cxt,
                    destination_assembly_cxt,
                    destination_module_cxt,
                    &sig,
                    &sig_len,
                    &imported_sig_buffer,
                    &imported_sig_buffer_size,
                    &remaining_imported_sig_length))
                {
                    free(imported_sig_buffer);
                    return false;
                }
            }
        }
        break;
    }

    *imported_sig_len = imported_sig_buffer_size - remaining_imported_sig_length;
    *imported_sig = imported_sig_buffer - *imported_sig_len; // Move back to the start of the buffer.
    return true;
}
