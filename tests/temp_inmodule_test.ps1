Describe 'Temp InModuleScope test' {
    InModuleScope 'NetClean' {
        It 'basic check' {
            # call a simple exported function
            Convert-RegKeyPath -Path 'HKLM:\SOFTWARE\\Test' | Should -Be 'HKLM\SOFTWARE\Test'
        }
    }
}
