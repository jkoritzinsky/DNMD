// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
//*****************************************************************************
// MetaModel.h -- header file for compressed COM+ metadata.
//

//
//*****************************************************************************
#ifndef _METAMODEL_H_
#define _METAMODEL_H_

#if _MSC_VER >= 1100
#pragma once
#endif

#include <cor.h>


#define ALLOCATED_MEMORY_MARKER 0xff

// Version numbers for metadata format.

#define METAMODEL_MAJOR_VER_V1_0 1      // Major version for v1.0
#define METAMODEL_MINOR_VER_V1_0 0      // Minor version for v1.0

#define METAMODEL_MAJOR_VER_V2_0 2      // Major version for v2.0
#define METAMODEL_MINOR_VER_V2_0 0      // Minor version for v2.0

#define METAMODEL_MAJOR_VER 2
#define METAMODEL_MINOR_VER 0

// Metadata version number up through Whidbey Beta2
#define METAMODEL_MAJOR_VER_B1 1
#define METAMODEL_MINOR_VER_B1 1


typedef enum MetadataVersion
{
    MDVersion1          = 0x00000001,
    MDVersion2          = 0x00000002,

    // @TODO - this value should be updated when we increase the version number
    MDDefaultVersion      = 0x00000002
} MetadataVersion;

struct HENUMInternal;

// This abstract defines the common functions that can be used for RW and RO internally
// (The primary user for this is Compiler\ImportHelper.cpp)
class IMetaModelCommon
{
public:
    __checkReturn
    virtual HRESULT CommonGetScopeProps(
        LPCSTR     *pszName,
        GUID        *pMvid) = 0;

    __checkReturn
    virtual HRESULT CommonGetTypeRefProps(
        mdTypeRef tr,
        LPCSTR     *pszNamespace,
        LPCSTR     *pszName,
        mdToken     *ptkResolution) = 0;

    __checkReturn
    virtual HRESULT CommonGetTypeDefProps(
        mdTypeDef td,
        LPCSTR     *pszNameSpace,
        LPCSTR     *pszName,
        DWORD       *pdwFlags,
        mdToken     *pdwExtends,
        ULONG       *pMethodList) = 0;

    __checkReturn
    virtual HRESULT CommonGetTypeSpecProps(
        mdTypeSpec ts,
        PCCOR_SIGNATURE *ppvSig,
        ULONG       *pcbSig) = 0;

    __checkReturn
    virtual HRESULT CommonGetEnclosingClassOfTypeDef(
        mdTypeDef  td,
        mdTypeDef *ptkEnclosingTypeDef) = 0;

    __checkReturn
    virtual HRESULT CommonGetAssemblyProps(
        USHORT      *pusMajorVersion,
        USHORT      *pusMinorVersion,
        USHORT      *pusBuildNumber,
        USHORT      *pusRevisionNumber,
        DWORD       *pdwFlags,
        const void  **ppbPublicKey,
        ULONG       *pcbPublicKey,
        LPCSTR     *pszName,
        LPCSTR     *pszLocale) = 0;

    __checkReturn
    virtual HRESULT CommonGetAssemblyRefProps(
        mdAssemblyRef tkAssemRef,
        USHORT      *pusMajorVersion,
        USHORT      *pusMinorVersion,
        USHORT      *pusBuildNumber,
        USHORT      *pusRevisionNumber,
        DWORD       *pdwFlags,
        const void  **ppbPublicKeyOrToken,
        ULONG       *pcbPublicKeyOrToken,
        LPCSTR     *pszName,
        LPCSTR     *pszLocale,
        const void  **ppbHashValue,
        ULONG       *pcbHashValue) = 0;

    __checkReturn
    virtual HRESULT CommonGetModuleRefProps(
        mdModuleRef tkModuleRef,
        LPCSTR     *pszName) = 0;

    __checkReturn
    virtual HRESULT CommonFindExportedType(
        LPCSTR     szNamespace,
        LPCSTR     szName,
        mdToken     tkEnclosingType,
        mdExportedType   *ptkExportedType) = 0;

    __checkReturn
    virtual HRESULT CommonGetExportedTypeProps(
        mdToken     tkExportedType,
        LPCSTR     *pszNamespace,
        LPCSTR     *pszName,
        mdToken     *ptkImpl) = 0;

    virtual int CommonIsRo() = 0;

    __checkReturn
    HRESULT CommonGetCustomAttributeByName( // S_OK or error.
        mdToken     tkObj,                  // [IN] Object with Custom Attribute.
        LPCSTR     szName,                 // [IN] Name of desired Custom Attribute.
        const void  **ppData,               // [OUT] Put pointer to data here.
        ULONG       *pcbData)               // [OUT] Put size of data here.
    {
        return CommonGetCustomAttributeByNameEx(tkObj, szName, NULL, ppData, pcbData);
    }

    __checkReturn
    virtual HRESULT CommonGetCustomAttributeByNameEx( // S_OK or error.
        mdToken            tkObj,            // [IN] Object with Custom Attribute.
        LPCSTR            szName,           // [IN] Name of desired Custom Attribute.
        mdCustomAttribute *ptkCA,            // [OUT] put custom attribute token here
        const void       **ppData,           // [OUT] Put pointer to data here.
        ULONG             *pcbData) = 0;     // [OUT] Put size of data here.

    __checkReturn
    virtual HRESULT FindParentOfMethodHelper(mdMethodDef md, mdTypeDef *ptd) = 0;

};  // class IMetaModelCommon



// An extension of IMetaModelCommon, exposed by read-only importers only.
//
// These methods were separated from IMetaModelCommon as
// Enc-aware versions of these methods haven't been needed
// and we don't want the maintainence and code-coverage cost
// of providing Enc-aware versions of these methods.
class IMetaModelCommonRO : public IMetaModelCommon
{
public:
    virtual HRESULT CommonGetMethodDefProps(
        mdMethodDef      tkMethodDef,
        LPCSTR         *pszName,
        DWORD           *pdwFlags,
        PCCOR_SIGNATURE *ppvSigBlob,
        ULONG           *pcbSigBlob
        ) = 0;

    virtual HRESULT CommonGetMemberRefProps(
        mdMemberRef      tkMemberRef,
        mdToken         *pParentToken
        ) = 0;

    virtual ULONG CommonGetRowCount(        // return hresult
        DWORD       tkKind) = 0;            // [IN] pass in the kind of token.

    virtual HRESULT CommonGetMethodImpls(
        mdTypeDef   tkTypeDef,              // [IN] typeDef to scope search
        mdToken    *ptkMethodImplFirst,     // [OUT] returns first methodImpl token
        ULONG      *pMethodImplCount        // [OUT] returns # of methodImpl tokens scoped to type
        ) = 0;

    virtual HRESULT CommonGetMethodImplProps(
        mdToken     tkMethodImpl,           // [IN] methodImpl
        mdToken    *pBody,                  // [OUT] returns body token
        mdToken    *pDecl                   // [OUT] returns decl token
        ) = 0;

    virtual HRESULT CommonGetCustomAttributeProps(
        mdCustomAttribute cv,               // [IN] CustomAttribute token.
        mdToken          *ptkObj,           // [OUT, OPTIONAL] Put object token here.
        mdToken          *ptkType,          // [OUT, OPTIONAL] Put AttrType token here.
        const void      **ppBlob,           // [OUT, OPTIONAL] Put pointer to data here.
        ULONG            *pcbSize) = 0;     // [OUT, OPTIONAL] Put size of date here.

    virtual HRESULT CommonGetFieldDefProps(
        mdFieldDef      tkFieldDef,
        mdTypeDef       *ptkParent,
        LPCSTR         *pszName,
        DWORD           *pdwFlags
        ) = 0;
}; // class IMetaModelCommonRO

//-----------------------------------------------------------------------------------------------------
// A common interface unifying RegMeta and MDInternalRO, giving the adapter a common interface to
// access the raw metadata.
//-----------------------------------------------------------------------------------------------------

// {4F8EE8A3-24F8-4241-BC75-C8CAEC0255B5}
EXTERN_GUID(IID_IMDCommon, 0x4f8ee8a3, 0x24f8, 0x4241, 0xbc, 0x75, 0xc8, 0xca, 0xec, 0x2, 0x55, 0xb5);

#undef  INTERFACE
#define INTERFACE IID_IMDCommon
DECLARE_INTERFACE_(IMDCommon, IUnknown)
{
    STDMETHOD_(IMetaModelCommon*, GetMetaModelCommon)() PURE;
    STDMETHOD_(IMetaModelCommonRO*, GetMetaModelCommonRO)() PURE;
    STDMETHOD(GetVersionString)(LPCSTR *pszVersionString) PURE;
};


#undef SETP
#undef _GETCDTKN
#undef _GETTKN
#undef _GETRID
#undef _GETBLOB
#undef _GETGUID
#undef _GETSTR
#undef SCHEMA

#endif // _METAMODEL_H_
// eof ------------------------------------------------------------------------
