#pragma once
#include <Windows.h>
#include <string>

#include <comdef.h>
#include <mscoree.h>
#include <metahost.h>

#import "mscorlib.tlb" raw_interfaces_only				\
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")
using namespace mscorlib;
#pragma comment(lib, "mscoree.lib")

#define CLRVersion L"v4.0.30319"
ICorRuntimeHost * Runtime = NULL;

static HRESULT LoadCLR ()
{
	if (Runtime != NULL)
		return S_OK;

	HRESULT hr;
	ICLRMetaHost *pMetaHost = NULL;
	ICLRRuntimeInfo *pRuntimeInfo = NULL;

	// Open the runtime
	hr = CLRCreateInstance (CLSID_CLRMetaHost, IID_PPV_ARGS (&pMetaHost));
	if (FAILED (hr))
		goto Cleanup;

	hr = pMetaHost->GetRuntime (CLRVersion, IID_PPV_ARGS (&pRuntimeInfo));
	if (FAILED (hr))
		goto Cleanup;

	// Check if the specified runtime can be loaded into the process.
	BOOL fLoadable;
	hr = pRuntimeInfo->IsLoadable (&fLoadable);
	if (FAILED (hr) || !fLoadable)
		goto Cleanup;

	// Load the CLR into the current process and return a runtime interface
	hr = pRuntimeInfo->GetInterface (CLSID_CorRuntimeHost, IID_PPV_ARGS (&(Runtime)));
	if (FAILED (hr))
		goto Cleanup;

	// Start the CLR.
	hr = Runtime->Start ();
	if (FAILED (hr))
		goto Cleanup;

Cleanup:

	if (pMetaHost)
	{
		pMetaHost->Release ();
		pMetaHost = NULL;
	}
	if (pRuntimeInfo)
	{
		pRuntimeInfo->Release ();
		pRuntimeInfo = NULL;
	}
	if (FAILED (hr) && Runtime)
	{
		Runtime->Release ();
		Runtime = NULL;
	}

	return hr;
}

static PVOID LoadAssembly (std::string assembly) {
	HRESULT hr;
	IUnknownPtr spAppDomainThunk = NULL;
	_AppDomainPtr apAppDomain = NULL;
	_AssemblyPtr spAssembly = NULL;

	if (Runtime == NULL) {
		hr = LoadCLR ();
		if (FAILED (hr)) return FALSE;
	}

	IUnknown* pIdentityArray = NULL;

	hr = Runtime->GetDefaultDomain(&spAppDomainThunk);
	if (FAILED (hr))
		return FALSE;

	// Get the current app domain
	hr = spAppDomainThunk->QueryInterface (IID_PPV_ARGS (&apAppDomain));
	if (FAILED (hr))
		return FALSE;

	// Load the assembly from bytes
	SAFEARRAYBOUND bounds[1];
	SAFEARRAY* arr;

	bounds[0].cElements = (ULONG)assembly.size ();
	bounds[0].lLbound = 0;

	arr = SafeArrayCreate (VT_UI1, 1, bounds);
	SafeArrayLock (arr);
	memcpy (arr->pvData, assembly.data (), assembly.size ());
	SafeArrayUnlock (arr);

	hr = apAppDomain->Load_3 (arr, &spAssembly);
	if (FAILED (hr))
		return FALSE;

	return spAssembly;
}

extern char * wchar_to_utf8 (const wchar_t *in);

static HRESULT CallMethod (PVOID assembly, std::string className, std::string methodName, std::string inputString, std::string & outputString) {
	HRESULT hr;
	_TypePtr spType = NULL;
	SAFEARRAY *psaStaticMethodArgs = NULL;
	variant_t vtPSInvokeReturnVal;
	variant_t vtEmpty;

	_AssemblyPtr spAssembly = reinterpret_cast<_Assembly *>(assembly);

	bstr_t bstrClassName(className.c_str());
	bstr_t bstrStaticMethodName(methodName.c_str());
	variant_t vtStringArg (inputString.c_str());

	hr = spAssembly->GetType_2 (bstrClassName, &spType);
	if (FAILED (hr)) return hr;
	if (!spType) return 0x80131512; // Missing member

	psaStaticMethodArgs = SafeArrayCreateVector (VT_VARIANT, 0, 1);
	LONG index = 0;
	hr = SafeArrayPutElement (psaStaticMethodArgs, &index, &vtStringArg);
	if (FAILED (hr)) return hr;

	// Invoke the method from the Type interface.
	hr = spType->InvokeMember_3 (
		bstrStaticMethodName,
		static_cast<BindingFlags>(BindingFlags_InvokeMethod | BindingFlags_Static | BindingFlags_Public),
		NULL,
		vtEmpty,
		psaStaticMethodArgs,
		&vtPSInvokeReturnVal);

	if (FAILED (hr)) return hr;

	SafeArrayDestroy (psaStaticMethodArgs);
	psaStaticMethodArgs = NULL;

	LPWSTR outputW = (LPWSTR)_bstr_t(vtPSInvokeReturnVal.bstrVal).copy();
	VariantClear (&vtPSInvokeReturnVal);

	LPSTR output = wchar_to_utf8(outputW);
	outputString = std::string (output);
	free(output);

	return S_OK;
}