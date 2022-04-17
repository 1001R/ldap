package ldap

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	NTLMBUF_LEN                      = 12000
	SEC_I_CONTINUE_NEEDED            = 0x00090312
	SEC_I_COMPLETE_NEEDED            = 0x00090313
	SEC_I_COMPLETE_AND_CONTINUE      = 0x00090314
	SECPKG_CRED_INBOUND         uint = 1
	SECPKG_CRED_OUTBOUND        uint = 2
	SECPKG_CRED_BOTH            uint = 3
)

type NTLMContext struct {
	cred w32SecHandle
	ctxt w32SecHandle
}

type w32TimeStamp struct {
	LowPart  uint32
	HighPart int32
}

type w32SecHandle struct {
	dwLower uintptr
	dwUpper uintptr
}

type w32SecBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   *byte
}

type w32SecBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  *w32SecBuffer
}

var secur32 *w32LibSecurity

type w32LibSecurity struct {
	handle                        syscall.Handle
	addrAcquireCredentialsHandle  uintptr
	addrInitializeSecurityContext uintptr
	addrCompleteAuthToken         uintptr
	addrFreeCredentialsHandle     uintptr
}

type SecBuffer struct {
	raw  []byte
	Buf  w32SecBuffer
	Desc w32SecBufferDesc
}

func NewOutputBuffer(size uint32) *SecBuffer {
	raw := make([]byte, size)
	r := SecBuffer{
		raw: raw,
		Buf: w32SecBuffer{
			BufferType: 2,
			pvBuffer:   &raw[0],
			cbBuffer:   size,
		},
		Desc: w32SecBufferDesc{
			ulVersion: 0,
			cBuffers:  1,
		},
	}
	r.Desc.pBuffers = &r.Buf
	return &r
}

func NewInputBuffer(input []byte) *SecBuffer {
	r := SecBuffer{
		raw: input,
		Buf: w32SecBuffer{
			BufferType: 2,
			pvBuffer:   &input[0],
			cbBuffer:   uint32(len(input)),
		},
		Desc: w32SecBufferDesc{
			ulVersion: 0,
			cBuffers:  1,
		},
	}
	r.Desc.pBuffers = &r.Buf
	return &r
}

func (b *SecBuffer) Copy() []byte {
	cp := make([]byte, b.Buf.cbBuffer)
	copy(cp, b.raw)
	return cp
}

func loadLibSecurity() (*w32LibSecurity, error) {
	dll, err := syscall.LoadLibrary("secur32.dll")
	if err != nil {
		return nil, err
	}
	s := &w32LibSecurity{
		handle:                        dll,
		addrAcquireCredentialsHandle:  getProcAddress(dll, "AcquireCredentialsHandleW"),
		addrInitializeSecurityContext: getProcAddress(dll, "InitializeSecurityContextW"),
		addrCompleteAuthToken:         getProcAddress(dll, "CompleteAuthToken"),
		addrFreeCredentialsHandle:     getProcAddress(dll, "FreeCredentialsHandle"),
	}
	return s, nil
}

func getProcAddress(module syscall.Handle, procname string) uintptr {
	if addr, err := syscall.GetProcAddress(module, procname); err != nil {
		panic(err)
	} else {
		return uintptr(addr)
	}
}

func (s *w32LibSecurity) Release() error {
	return syscall.FreeLibrary(s.handle)
}

func (s *w32LibSecurity) AcquireCredentialsHandle(principal, pkgname string, credentialUse uint, credential *w32SecHandle) (uint, error) {
	var pszPackage *uint16
	var pszPrincipal *uint16
	if pkgname != "" {
		if p, err := syscall.UTF16PtrFromString(pkgname); err == nil {
			pszPackage = p
		} else {
			return 0, fmt.Errorf("invalid security package: %v", pkgname)
		}
	}
	if principal != "" {
		if p, err := syscall.UTF16PtrFromString(principal); err == nil {
			pszPackage = p
		} else {
			return 0, fmt.Errorf("invalid principal: %v", principal)
		}
	}
	var expiry w32TimeStamp
	rv, _, _ := syscall.SyscallN(s.addrAcquireCredentialsHandle,
		uintptr(unsafe.Pointer(pszPrincipal)),
		uintptr(unsafe.Pointer(pszPackage)),
		uintptr(credentialUse),
		0, // pvLogonID
		0, // pAuthData
		0, // pGetKeyFn
		0, // pvGetKeyArgument
		uintptr(unsafe.Pointer(credential)),
		uintptr(unsafe.Pointer(&expiry)),
	)
	return uint(rv), nil
}

func (s *w32LibSecurity) InitializeSecurityContext(credential, context *w32SecHandle, fContextReq uint32, targetDataRep uint32, input *SecBuffer, newContext *w32SecHandle, output *SecBuffer) uint32 {
	var pInput *w32SecBufferDesc
	var pOutput *w32SecBufferDesc
	var attrs uint32
	var ts w32TimeStamp

	if input != nil {
		pInput = &input.Desc
	}
	if output != nil {
		pOutput = &output.Desc
	}

	rv, _, _ := syscall.SyscallN(s.addrInitializeSecurityContext,
		uintptr(unsafe.Pointer(credential)),
		uintptr(unsafe.Pointer(context)),
		0, // pszTargetName
		uintptr(fContextReq),
		0, // Reserved1
		uintptr(targetDataRep),
		uintptr(unsafe.Pointer(pInput)),
		0, // Reserved2
		uintptr(unsafe.Pointer(newContext)),
		uintptr(unsafe.Pointer(pOutput)),
		uintptr(unsafe.Pointer(&attrs)),
		uintptr(unsafe.Pointer(&ts)),
	)
	return uint32(rv)
}

func (s *w32LibSecurity) CompleteAuthToken(context *w32SecHandle, token *SecBuffer) uint32 {
	rv, _, _ := syscall.SyscallN(s.addrCompleteAuthToken,
		uintptr(unsafe.Pointer(context)),
		uintptr(unsafe.Pointer(&token.Desc)),
	)
	return uint32(rv)
}

func (s *w32LibSecurity) FreeCredentialsHandle(credential *w32SecHandle) uint32 {
	rv, _, _ := syscall.SyscallN(s.addrFreeCredentialsHandle, uintptr(unsafe.Pointer(credential)))
	return uint32(rv)
}

func NewNTLM() (*NTLMContext, error) {
	var ntlmContext NTLMContext
	return &ntlmContext, nil
}

func (c *NTLMContext) Start() ([]byte, error) {
	if rv, err := secur32.AcquireCredentialsHandle("", "NTLM", SECPKG_CRED_OUTBOUND, &c.cred); err != nil || rv != 0 {
		if err != nil {
			return nil, fmt.Errorf("win32 error - AcquireCredentialsHandle: %v", err)
		} else {
			return nil, fmt.Errorf("win32 error - AcquireCredentialsHandle -> %d", rv)
		}
	}
	output := NewOutputBuffer(NTLMBUF_LEN)
	rv := secur32.InitializeSecurityContext(&c.cred, nil, 0x800, 0, nil, &c.ctxt, output)
	var err error
	if rv == SEC_I_COMPLETE_AND_CONTINUE || rv == SEC_I_COMPLETE_NEEDED {
		if secur32.CompleteAuthToken(&c.ctxt, output) != 0 {
			err = fmt.Errorf("win32 error - CompleteAuthToken -> %x", rv)
		}
	} else if rv != 0 && rv != SEC_I_CONTINUE_NEEDED {
		err = fmt.Errorf("win32 error: InitializeSecurityContext -> %x", rv)
	}
	if err != nil {
		secur32.FreeCredentialsHandle(&c.cred)
		return nil, err
	}
	return output.Copy(), nil
}

func (c *NTLMContext) Complete(challenge []byte) ([]byte, error) {
	inBuf := NewInputBuffer(challenge)
	outBuf := NewOutputBuffer(NTLMBUF_LEN)
	defer secur32.FreeCredentialsHandle(&c.cred)
	rv := secur32.InitializeSecurityContext(&c.cred, &c.ctxt, 0x800, 0, inBuf, &c.ctxt, outBuf)
	if rv == SEC_I_COMPLETE_AND_CONTINUE || rv == SEC_I_COMPLETE_NEEDED {
		if secur32.CompleteAuthToken(&c.ctxt, outBuf) != 0 {
			return nil, fmt.Errorf("win32 error - CompleteAuthToken -> %x", rv)
		}
	} else if rv != 0 && rv != SEC_I_CONTINUE_NEEDED {
		return nil, fmt.Errorf("win32 error - InitializeSecurityContext -> %x", rv)
	}
	return outBuf.Copy(), nil
}

// NTLMBind performs an NTLMSSP Bind using Windows credentials
func (l *Conn) NTLMBindSSO(domain string) error {
	ntlm, err := NewNTLM()
	if err != nil {
		return err
	}
	req := &NTLMBindRequest{
		Domain: domain,
		createNegotiateMessage: func() ([]byte, error) {
			return ntlm.Start()
		},
		processChallenge: func(challenge []byte) ([]byte, error) {
			return ntlm.Complete(challenge)
		},
	}
	_, err = l.NTLMChallengeBind(req)
	return err
}

func init() {
	if s, err := loadLibSecurity(); err != nil {
		panic(err)
	} else {
		secur32 = s
	}
}
