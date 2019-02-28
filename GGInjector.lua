------------------------------------------------------------------
-- Author: saiaapiz
-- GGInjector									Build: 19-2-2019
-- Only for ARMv7.
-- Thanks to enyby for great app, and help.
------------------------------------------------------------------

------------------------=// Declaration //=--------------------------
sf	= string.format

------------------------=// Internal Function //=--------------------------
function openFile(path, perm)
	gg.alert(path.."-> "..perm)
	local _ = io.open(path, perm)
	if _ ~= nil then return _ end
	return nil
end
function readFile(path)
	local _ = openFile(path, 'rb')
	local __ = _:read("*a") _:close()
	return __
end
function writeFile(path, data) 
	local _ = openFile(path, 'wb')
	_:write(data) _:close() 
end
function popupbox(caption, text)
	assert(caption ~= nil, "\n\n>> [popupbox]: error, caption was nil. <<\n\n")
	if text == nil then
		text = caption
		caption = "[Info]: Notice"
	end
	gg.alert(caption .. "\n\t- " .. text)
end
function tohex(Data) 
	return Data:gsub(".", function(a) return string.format("%02X", (string.byte(a))) end):gsub(" ", "") 
end
function wpm(address, ggtype, data)
	assert(address ~= nil, "\n\n>> [wpm]: error, provided address is nil. <<\n\n")
	if gg.setValues({{address = address, flags = ggtype, value = data}}) then 
		return true 
	else 
		return false 
	end
end
function rpm(address, ggtype)
	assert(address ~= nil, "\n\n>> [rpm]: error, provided address is nil. <<\n\n")
	res = gg.getValues({{address = address, flags = ggtype}})
	if type(res) ~= "string" then
		if ggtype == gg.TYPE_BYTE then
			result = res[1].value & 0xFF
		elseif ggtype == gg.TYPE_WORD then
			result = res[1].value & 0xFFFF
		elseif ggtype == gg.TYPE_DWORD then
			result = res[1].value & 0xFFFFFFFF
		elseif ggtype == gg.TYPE_QWORD then
			result = res[1].value & 0xFFFFFFFFFFFFFFFF
		elseif ggtype == gg.TYPE_XOR then
			result = res[1].value & 0xFFFFFFFF
		else
			result = res[1].value
		end
		return result
	else
		return false
	end
end
function rwmem(address, SizeOrBuffer)
	assert(type(address) ~= "string", "\n\n>> [rwmem]: error, address is string. Please check caller. <<\n\n")
	assert(address ~= nil, "\n\n>> [rwmem]: error, provided address is nil. <<\n\n")
	_rw = {}
	if type(SizeOrBuffer) == "number" then
		_ = ""
		for _ = 1, SizeOrBuffer do _rw[_] = {address = (address - 1) + _, flags = gg.TYPE_BYTE} end
		for v, __ in ipairs(gg.getValues(_rw)) do _ = _ .. string.format("%02X", __.value & 0xFF) end
		return _
	end
	Byte = {} SizeOrBuffer:gsub("..", function(x) 
		Byte[#Byte + 1] = x _rw[#Byte] = {address = (address - 1) + #Byte, flags = gg.TYPE_BYTE, value = x .. "h"} 
	end)
	gg.setValues(_rw)
end
function rdstr(address, strsz)
  assert(address ~= nil, "\n\n>> [rdstr]: error, provided address is nil. <<\n\n")
  if strsz == nil or type(strsz) ~= "number" then strsz = 128 end
  local str = ""
  for _ in rwmem(address, strsz):gmatch("..") do
    if _ == "00" then break end
      str = str .. string.char(tonumber(_, 16))
  end
  return str
end
function scanaob(AobByte, Line, Region)
	gg.clearResults(); oRange = gg.getRanges()
	if Region ~= nil and oRange ~= Region then gg.setRanges(Region) end
	gg.internal1(AobByte:gsub("..", function(a) return string.format("%c", tonumber(a, 16)) end))
	_ = gg.getResultCount()
	if _ <= Line then return nil end
	Address = gg.getResults(_)[Line].address
	gg.clearResults(); gg.setRanges(oRange)
	return Address
end

------------------------=//  Shared Library Things  //=--------------------------
function getLibraryBase(lib)
	for _, __ in pairs(gg.getRangesList(lib)) do
		if __["state"] == "Xa" or __["state"] == "Xs" then return __["start"], __["end"] end
	end
	return nil
end
function getLibInformation(LibName)
	local LibBase = getLibraryBase(LibName)
	if LibBase ~= nil then
		_ = gg.getValues({
			{address = LibBase, flags = gg.TYPE_DWORD },		-- Magic
			-- EI_PAD skipped --
			{address = LibBase + 0x12, flags = gg.TYPE_WORD },	-- Machine
			{address = LibBase + 0x1C, flags = gg.TYPE_DWORD },	-- Program Header Table (PH) Offset
			{address = LibBase + 0x24, flags = gg.TYPE_DWORD },	-- Flags
			{address = LibBase + 0x2A, flags = gg.TYPE_WORD },	-- Program Header Table (PH) Size Entry
			{address = LibBase + 0x2C, flags = gg.TYPE_WORD },	-- Number Of Entries In Program Header Table (PH) 
			})
		local Elf = { -- Elf Information Table Structure--
			Magic		= _[1].value,
			Machine 	= _[2].value,
			PHOffset 	= _[3].value,
			Flags 		= _[4].value,
			PHSize 		= _[5].value,
			PHNum		= _[6].value,
			pHdr		= {},
			Dyn			= {},
			Sym			= {},
			vAddress	= LibBase
		}
		for _ = 1, Elf.PHNum do -- Parsing Program Header
			local _pHdr = LibBase + Elf.PHOffset + (_ * Elf.PHSize)
			local pHdr = gg.getValues({
				{ address = _pHdr, flags = gg.TYPE_DWORD }, 		-- p_type
				{ address = _pHdr + 4, flags = gg.TYPE_DWORD }, 	-- p_offset
				{ address = _pHdr + 8, flags = gg.TYPE_DWORD }, 	-- p_vaddr
				{ address = _pHdr + 0xC, flags = gg.TYPE_DWORD },	-- p_paddr
				{ address = _pHdr + 0x10, flags = gg.TYPE_DWORD },	-- p_filesz
				{ address = _pHdr + 0x14, flags = gg.TYPE_DWORD },	-- p_memsz
				{ address = _pHdr + 0x18, flags = gg.TYPE_DWORD },	-- p_flags
				{ address = _pHdr + 0x1C, flags = gg.TYPE_DWORD },	-- p_align
			})
			Elf.pHdr[_] = { -- All data in Program Header now in Elf.pHdr[Elf.PHNum]
				p_type		= pHdr[1].value,
				p_offset	= pHdr[2].value,
				p_vaddr		= pHdr[3].value,
				p_paddr		= pHdr[4].value,
				p_filesz	= pHdr[5].value,
				p_memsz		= pHdr[6].value,
				p_flags		= pHdr[7].value,
				p_align		= pHdr[8].value
			}
		end
		for _ = 1, Elf.PHNum do  -- Parsing Dynamic Segment
			if Elf.pHdr[_].p_type == 2 then -- PT_DYNAMIC
				local DynCount = 0
				while true do
					local _Dyn = gg.getValues({
						{ address = LibBase + Elf.pHdr[_].p_vaddr + (DynCount * 8), flags = gg.TYPE_DWORD }, -- d_tag
						{ address = LibBase + Elf.pHdr[_].p_vaddr + 4 + (DynCount * 8), flags = gg.TYPE_DWORD } -- d_ptr / d_val
					})
					if _Dyn[1].value == 0 and _Dyn[2].value == 0 then break end -- End of dynamic segment
					DynCount = DynCount + 1 -- Keep growing !
					Elf.Dyn[DynCount] = { -- All data in Dynamic Segment now in Elf.Dyn[Section]
						d_tag = _Dyn[1].value, 
						d_val = _Dyn[2].value, 
						d_ptr = _Dyn[2].value 
					}
				end
			end
		end
		return Elf
	end
	return nil
end
function getSymbolAddress(ElfData, symName)
	assert(ElfData ~= nil, "\n\n>> [getSymbolAddress]: error, provided ElfData is nil. <<\n\n")
	for _ = 1, #ElfData.Dyn do
			if tonumber(ElfData.Dyn[_].d_tag) == 4 then nChain = gg.getValues({{address = (ElfData.Dyn[_].d_ptr + 4) + ElfData.vAddress, flags = gg.TYPE_DWORD}})[1].value end
			if tonumber(ElfData.Dyn[_].d_tag) == 5 then strtab = ElfData.Dyn[_].d_ptr + ElfData.vAddress end
			if tonumber(ElfData.Dyn[_].d_tag) == 6 then symtab = ElfData.Dyn[_].d_ptr + ElfData.vAddress end
	end
	if nChain ~= nil then
		for _ = 1, nChain do
			local sym = symtab + (_ * 0x10)
			__ = gg.getValues({
				{ address = sym, flags = gg.TYPE_DWORD },		-- st_name
				{ address = sym + 0x4, flags = gg.TYPE_DWORD },	-- st_value
			})
			if rdstr(strtab + __[1].value) == symName then
				return ElfData.vAddress + __[2].value
			end
		end
	end
	return nil
end

------------------------=// Assembly Hooking //=---------------------------
function reverseAddress(address)
	assert(address ~= nil, "\n\n>> [reverseAddress]: error, provided address is nil. <<\n\n")
	return (address & 0x000000FF) << 24 | (address & 0x0000FF00) << 8 | (address & 0x00FF0000) >> 8 | (address & 0xFF000000) >> 24
end
function setjmp(address, target)
	assert(address ~= nil, "\n\n>> [setjmp]: error, provided address is nil. <<\n\n")
	assert(address ~= nil, "\n\n>> [setjmp]: error, provided target address is nil. <<\n\n")
	local o_opsc = rwmem(address, 8)
	rwmem(address, "04F01FE5"..string.format("%08x", reverseAddress(target))) -- LDR	PC, [PC, #-4]
	return function() rwmem(address, o_opsc) end -- jmp Restored
end
function prephook(address, writeoricode)
	assert(address ~= nil, "\n\n>> [prephook]: error, provided address is nil. <<\n\n")
	local _alloc	= gg.allocatePage(gg.PROT_READ | gg.PROT_WRITE | gg.PROT_EXEC)
	gg.sleep(100) -- make sure allocated mem is ready.
	if writeoricode then rwmem(_alloc, _oriop) end
	return _alloc + (writeoricode == true and 0x8 or 0), address + 0x8 -- allocated address, fixed allocated address, next instruction address, original opcode.
end
function getregister(address, reg)
	assert(address ~= nil, "\n\n>> [getregister]: error, provided address is nil. <<\n\n")
	
	_getregsc, n_address = prephook(address, true)												-- Prepare allocated memory.
	
	rwmem(_getregsc, "04"..string.format("%02X", (reg & 0xFF) << 4).."8FE504F01FE50000000000000000")	-- Write shellcode.
	wpm(_getregsc + 0x8, 4, n_address)																	-- Write Return Address.
	
	local r_restorereg = setjmp(address, _getregsc - 0x8)  																	-- Hook targeted address.
	
	return _getregsc + 0xC, r_restorereg																	-- Return: Register Retriever Address, Hook restorer function.
end

------------------------=// Injector Function //=---------------------------
function getLib(libName)
	gg.toast("Searching for '"..libName.."', This may take a while. Please wait...")
	local m_lib = getLibInformation(libName)
	if m_lib ~= nil then 
		--print(sf("[getLib]: %s Architecture: 0x%08X", libName, m_lib.Machine))
		if m_lib.Machine == 0x28 then -- ARM32
			return m_lib 
		end
		popupbox("[Error]: Unsupported Device !", "Currently, only ARM32 device are supported.")
		os.exit()
		return nil
	end 
	
	popupbox("[Error]: Missing dependencies !", "One of required shared library '" .. libName .. "', has left us in the dark.")
	os.exit()
	return nil
end
function getSymbol(ElfData, Symname)
	local s_address = getSymbolAddress(ElfData, Symname)
	if s_address ~= nil then 
		return s_address 
	end
	
	popupbox("[Error]: Missing dependencies !", "One of required symbol '" .. Symname .. "', has been reported missing.")
	os.exit()
	return nil
end
function injectShared(libPath) -- Inject any shared library as long it from /data
	local m_libRS		= getLib("libRS.so")
	local m_libdl		= getLib("libdl.so")
	local m_libc		= getLib("libc.so")

	local s_dlopen	= getSymbol(m_libdl, "dlopen")
	local s_getuid	= getSymbol(m_libc, "getuid")
	
	local libPath	= tohex(libPath) .. "00"
	local o_opsc	= rwmem(s_getuid, 8)
	
	local s_code	= o_opsc .. "FF5F2DE92810DFE5000051E30500001A20009FE50210B0E31CE09FE51C209FE512FF2FE108008FE5FF5FBDE804F01FE5AAAAAAAA00000000CCCCCCCCDDDDDDDDEEEEEEEE"
	
	local a_alloc	= gg.allocatePage(gg.PROT_READ | gg.PROT_WRITE | gg.PROT_EXEC)
	local a_shellcode, a_path = a_alloc, a_alloc + s_code:len() / 2
	
	rwmem(a_path, libPath)
	rwmem(a_shellcode, s_code) 
	
	a_shellcode = a_shellcode + 0x8
	wpm(a_shellcode + 0x30, 4, s_getuid + 0x8)		-- Return Address
	wpm(a_shellcode + 0x38, 4, a_path)				-- Path Address
	wpm(a_shellcode + 0x3C, 4, m_libRS.vAddress)	-- LR Address
	wpm(a_shellcode + 0x40, 4, s_dlopen)			-- dlopen Address
	
	gg.toast("Injecting ...")
	local r_fakereturn	= setjmp(m_libRS.vAddress, a_shellcode + 0x24)
	local r_hookaddress	= setjmp(s_getuid, a_shellcode - 0x8)
	
	local libHandle = 0
	while libHandle == 0 do
		libHandle = rpm(a_shellcode + 0x34, 4)
	end
	
	gg.sleep(100) -- Let hope program doesnt crash !
	r_fakereturn()
	r_hookaddress()
	
	popupbox("[Info]: Injected !", sf("Handle: 0x%08X", libHandle))
	print("\nShared Library Injected !\n"..sf("Handle: 0x%08X", libHandle))
	
	return a_shellcode + 0x34 -- Return Injected Lib Handle
end

------------------------=// #> Main Code <# //=---------------------------
SharedLibPath = "/data/local/tmp/libProjectHello.so"
injectShared(SharedLibPath)
os.exit()

-- TODO: Waiting for chmod feature by Enyby T_T.
while true do
::wait_input::
	local _input = gg.prompt({[[▄▀▀ ▄▀▄ ▀ ▄▀▄ ▄▀▄ █▀▄ ▀ ▀▀▀▀█
░▀▄ █▀█ █ █▀█ █▀█ █░█ █ ░▄▀▀░
▀▀░ ▀░▀ ▀ ▀░▀ ▀░▀ █▀░ ▀ ▀▀▀▀▀
                  .: aPizInjector - ARMv7 :.
* Note: Not tested on different architecture.

Select shared library: ]]}, {gg.getFile():gsub("[^/]+$","")}, {"file"})
	if _input == nil or string.len(_input[1]) == 0 then
		if gg.alert("Exit Injector ?", "> Exit <", "> Go Back <") == 1 then break else goto wait_input end
	end
	
	local f_path = gg.CACHE_DIR.."/".._input[1]:match("[^/]-$")
	if openFile(_input[1], "r") == nil then popupbox("[Error]: IO Error !", "Failed reading '" .. _input[1] .. "', make sure file exist on disk.\nPlease try again.") goto wait_input end
	
	local d_input = readFile(_input[1])
	writeFile(f_path, d_input)

	injectShared(f_path)
	os.remove(f_path)
	break
end





























