
// ****************************************************************************
// File: Main.h
// Desc:
//
// ****************************************************************************

extern void fixEa(ea_t ea);
extern void fixDword(ea_t eaAddress);
extern void fixFunction(ea_t eaFunc);
extern void setUnknown(ea_t ea, int size);
extern BOOL getVerifyEa(ea_t ea, ea_t &rValue);
extern BOOL hasAnteriorComment(ea_t ea);
extern void killAnteriorComments(ea_t ea);
#if IDA_SDK_VERSION < 900
extern int  addStrucMember(struc_t *sptr, char *name, ea_t offset, flags_t flag, opinfo_t *type, asize_t nbytes);
#endif
extern void addTableEntry(UINT flags, ea_t vft, int methodCount, LPCSTR format, ...);
extern BOOL getPlainTypeName(__in LPCSTR mangled, __out_bcount(MAXSTR) LPSTR outStr);
extern void setName(ea_t ea, __in LPCSTR name);
extern void setComment(ea_t ea, LPCSTR comment, BOOL rptble);
extern void setAnteriorComment(ea_t ea, const char *format, ...);

// Return TRUE if there is a name at address that is not a dumbly name
inline BOOL hasName(ea_t ea) { return has_name(get_flags(ea)); }

// Return TRUE if there is a comment at address
inline BOOL hasComment(ea_t ea) { return has_cmt(get_flags(ea)); }


// Get IDA 32 bit value with verification
template <class T> BOOL getVerify32(ea_t eaPtr, T &rValue)
{
	// Location valid?
    if (is_loaded(eaPtr))
	{
		// Get 32bit value
		rValue = (T) get_32bit(eaPtr);
		return(TRUE);
	}

	return(FALSE);
}

#if IDA_SDK_VERSION < 800
#define EA_SIZE sizeof(ea_t)
#else
#define EA_SIZE EAH.ea_size
#endif

extern BOOL isDatabase64Bit;

// Get address/pointer value
inline ea_t getEa(ea_t ea)
{
    return isDatabase64Bit ? get_64bit(ea) : get_32bit(ea);
}


// Returns TRUE if ea_t sized value flags
inline BOOL isEa(flags_t f)
{
    return isDatabase64Bit ? is_qword(f) : is_dword(f);
}

extern BOOL optionPlaceStructs;
extern BOOL optionPlaceAtNamed;
