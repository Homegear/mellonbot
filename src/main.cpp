#include "GnuTls.h"

#include <homegear-base/BaseLib.h>
#include <iostream>
#include "../config.h"

enum class Operations {
  kRenew,
  kCreateToken,
  kExchangeToken,
  kSignCsr,
  kCreateAndSignCsr
};

static constexpr const char *caCerts = "-----BEGIN CERTIFICATE-----\n"
                                       "MIICOTCCAb+gAwIBAgIUQJyNBzPv71qxFCZcvSdkEP9i480wCgYIKoZIzj0EAwIw\n"
                                       "TTELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJXMRUwEwYDVQQKDAxTZW5zYXJ1IEdt\n"
                                       "YkgxGjAYBgNVBAMMEVNlbnNhcnUgUm9vdCBDQSA1MCAXDTIyMTExNTEyMjE1MloY\n"
                                       "DzIwNzIxMjIxMTIyMTUyWjBVMQswCQYDVQQGEwJERTELMAkGA1UECAwCQlcxFTAT\n"
                                       "BgNVBAoMDFNlbnNhcnUgR21iSDEiMCAGA1UEAwwZU2Vuc2FydSBJbnRlcm1lZGlh\n"
                                       "dGUgQ0EgNTB2MBAGByqGSM49AgEGBSuBBAAiA2IABMmc+GNqjwJ/REvcvcBFtUx4\n"
                                       "fHXmQCzA9tZJ8d7WCBNMgMx1kf8lpDomRZyVNBkLZYbFr+qGz7cKhgXesDJhSpsh\n"
                                       "0XNcS1pupfOBPdWBfSu9Jc05GYKeLkuBMtj6i/NrrKNWMFQwHQYDVR0OBBYEFMXJ\n"
                                       "Affl1/+a53aWT2rs1O1AFMN0MB8GA1UdIwQYMBaAFEEjNyUM3knyAH9yl3Ko5Zj8\n"
                                       "KuscMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0EAwIDaAAwZQIwAe4Rk5oI\n"
                                       "v0W/fiSmTWdzexFDQGi/Shg8LUWo/MotX3owI/RFfyGXu5KYNExEUQQUAjEAydXB\n"
                                       "EBeV7Ik4g1chXeJBafpWtfzXgkxhjI1628PgH+E+03M5qj4OYNjRFBwr36fE\n"
                                       "-----END CERTIFICATE-----\n";

static constexpr const char *imCerts[11] = {"-----BEGIN CERTIFICATE-----\n"
                                            "MIICODCCAb+gAwIBAgIUBY87tCUOuOGui4uM1CUMhsb9tjEwCgYIKoZIzj0EAwIw\n"
                                            "TTELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJXMRUwEwYDVQQKDAxTZW5zYXJ1IEdt\n"
                                            "YkgxGjAYBgNVBAMMEVNlbnNhcnUgUm9vdCBDQSAxMCAXDTIyMTExNTEyMTk1NVoY\n"
                                            "DzIwNzIxMjIxMTIxOTU1WjBVMQswCQYDVQQGEwJERTELMAkGA1UECAwCQlcxFTAT\n"
                                            "BgNVBAoMDFNlbnNhcnUgR21iSDEiMCAGA1UEAwwZU2Vuc2FydSBJbnRlcm1lZGlh\n"
                                            "dGUgQ0EgMTB2MBAGByqGSM49AgEGBSuBBAAiA2IABMoBq0Dh//DGZsqerNYr5Kpe\n"
                                            "pAHE+0XVXYN8A1EL2WzRFPG9QX6CW12PMI6JVhRjAbRlOHkjKdNtN4FhzeMLA9/L\n"
                                            "b5KaM07Gg3P2zasQExlAeOQj1kPJ93NRgtUNJk8I1qNWMFQwHQYDVR0OBBYEFIG2\n"
                                            "OIvTWX4FyCIiZ0nNOZ7dXQtkMB8GA1UdIwQYMBaAFMYwuddXgxICfyaG7OYyNCKo\n"
                                            "CPgBMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0EAwIDZwAwZAIwT3RSnZPg\n"
                                            "Tc216PRYqiJwO3kniHKB/3gCKNwE7cqFCZF1ULWRbeG2mGlDwcE8Zq5wAjBYIMja\n"
                                            "kzDypz5LdNRc3lvLjusGZSJhWeLNWLd6C3t+60OKuXQscM8fTa877Cyu7H0=\n"
                                            "-----END CERTIFICATE-----\n",
                                            "-----BEGIN CERTIFICATE-----\n"
                                            "MIICODCCAb+gAwIBAgIUF36rssnHygYfoaPvWZLVuK/bQzkwCgYIKoZIzj0EAwIw\n"
                                            "TTELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJXMRUwEwYDVQQKDAxTZW5zYXJ1IEdt\n"
                                            "YkgxGjAYBgNVBAMMEVNlbnNhcnUgUm9vdCBDQSAyMCAXDTIyMTExNTEyMjAxNloY\n"
                                            "DzIwNzIxMjIxMTIyMDE2WjBVMQswCQYDVQQGEwJERTELMAkGA1UECAwCQlcxFTAT\n"
                                            "BgNVBAoMDFNlbnNhcnUgR21iSDEiMCAGA1UEAwwZU2Vuc2FydSBJbnRlcm1lZGlh\n"
                                            "dGUgQ0EgMjB2MBAGByqGSM49AgEGBSuBBAAiA2IABDyWQ4LPXSOz9xbIXYHbq9Ud\n"
                                            "Qpn3P2KiJKxTzRhRQt4VKqoBRbhLZH/gdUBpVrYizhWE6VXkfm3RCIyNkwC0S1ZG\n"
                                            "nyYTGI/fadEiykvnQa/yBrEifOM7ihaZIQDSu8D5wqNWMFQwHQYDVR0OBBYEFPKO\n"
                                            "mYCKhYvpug3sOdA2Spc4h3iUMB8GA1UdIwQYMBaAFNmL19dULMxdcVjGnVOM0r1h\n"
                                            "aTQXMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0EAwIDZwAwZAIwTB++19Ud\n"
                                            "ClO7ckEfDMmKapDRCHObXIGY2ux6tYpDOOibrKHjkTT+D5goB51XpRqXAjAh44P4\n"
                                            "CjWrqhomHqdFji0a0Bk2od4ib2x4JHQDVwr6TESFkyCdyH/wj7CZUAEkV8U=\n"
                                            "-----END CERTIFICATE-----\n",
                                            "-----BEGIN CERTIFICATE-----\n"
                                            "MIICODCCAb+gAwIBAgIUYWjJm54MxuiCeZZ6q1Esv3ZYbPgwCgYIKoZIzj0EAwIw\n"
                                            "TTELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJXMRUwEwYDVQQKDAxTZW5zYXJ1IEdt\n"
                                            "YkgxGjAYBgNVBAMMEVNlbnNhcnUgUm9vdCBDQSAzMCAXDTIyMTExNTEyMjAzOFoY\n"
                                            "DzIwNzIxMjIxMTIyMDM4WjBVMQswCQYDVQQGEwJERTELMAkGA1UECAwCQlcxFTAT\n"
                                            "BgNVBAoMDFNlbnNhcnUgR21iSDEiMCAGA1UEAwwZU2Vuc2FydSBJbnRlcm1lZGlh\n"
                                            "dGUgQ0EgMzB2MBAGByqGSM49AgEGBSuBBAAiA2IABFLBkixPR4ZkBDyzPcvpLEbn\n"
                                            "jdWTTIon9MIyGRqq/++X1bS0o8J0pKwXiz4ZDchRPpo2krFOHwTewZZNS63yem7/\n"
                                            "jblU98tsWaG0CpXkt6kGMqRKqoNlLM1fwBFk1cFCtqNWMFQwHQYDVR0OBBYEFBYR\n"
                                            "t5+R+PTI3Z084jo2HCAkxhAAMB8GA1UdIwQYMBaAFOv5FwOuErFjODlsKBC6ceKz\n"
                                            "wvRxMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0EAwIDZwAwZAIwYUjd1T4/\n"
                                            "nEKSFX8CvfaIMfTTYINJTzfxemQA1RCQAEQWBO/K7JD51jdiJhIL9uYpAjA2PtSt\n"
                                            "feMJO0k3j66qsManAOxnhiG/GjPvTNaCypnLV75hBnkRoGgk+cme1Ba+7y8=\n"
                                            "-----END CERTIFICATE-----\n",
                                            "-----BEGIN CERTIFICATE-----\n"
                                            "MIICOTCCAb+gAwIBAgIUXf9OqjMn9XzBZEDa9txOZ3KJXqswCgYIKoZIzj0EAwIw\n"
                                            "TTELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJXMRUwEwYDVQQKDAxTZW5zYXJ1IEdt\n"
                                            "YkgxGjAYBgNVBAMMEVNlbnNhcnUgUm9vdCBDQSA0MCAXDTIyMTExNTEyMjEzNloY\n"
                                            "DzIwNzIxMjIxMTIyMTM2WjBVMQswCQYDVQQGEwJERTELMAkGA1UECAwCQlcxFTAT\n"
                                            "BgNVBAoMDFNlbnNhcnUgR21iSDEiMCAGA1UEAwwZU2Vuc2FydSBJbnRlcm1lZGlh\n"
                                            "dGUgQ0EgNDB2MBAGByqGSM49AgEGBSuBBAAiA2IABP0Sk1lrgaaBaIj9PSj4Nh3j\n"
                                            "X8xepDQCpogDoH4PYV3sSo9Md3IZQu+107PbCov1A3OC7XAR5r6O+ZFM1421J9yd\n"
                                            "CfsYksBdzotadh7SYI7l4Am5pe8BY4xdYHeasmRt2KNWMFQwHQYDVR0OBBYEFCD2\n"
                                            "MNiUvGEovQwVGCFpL8pQJIW1MB8GA1UdIwQYMBaAFOEG8xbvXhpt7gGkas0XGFK6\n"
                                            "2+z6MBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0EAwIDaAAwZQIwEkZxIfJ5\n"
                                            "yUq2BxoynSVqXFxlQqIgVcC6CxoDtvgOU2ZBWvHL5POjLcc6WA3l25owAjEAwaGu\n"
                                            "dnONRzs0WRBMJfnr3mUUmf1Z/MB/Tp0y3wI+zV/Hs1oGzes5oRHTkpuSSTDx\n"
                                            "-----END CERTIFICATE-----\n",
                                            "-----BEGIN CERTIFICATE-----\n"
                                            "MIICOTCCAb+gAwIBAgIUQJyNBzPv71qxFCZcvSdkEP9i480wCgYIKoZIzj0EAwIw\n"
                                            "TTELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJXMRUwEwYDVQQKDAxTZW5zYXJ1IEdt\n"
                                            "YkgxGjAYBgNVBAMMEVNlbnNhcnUgUm9vdCBDQSA1MCAXDTIyMTExNTEyMjE1MloY\n"
                                            "DzIwNzIxMjIxMTIyMTUyWjBVMQswCQYDVQQGEwJERTELMAkGA1UECAwCQlcxFTAT\n"
                                            "BgNVBAoMDFNlbnNhcnUgR21iSDEiMCAGA1UEAwwZU2Vuc2FydSBJbnRlcm1lZGlh\n"
                                            "dGUgQ0EgNTB2MBAGByqGSM49AgEGBSuBBAAiA2IABMmc+GNqjwJ/REvcvcBFtUx4\n"
                                            "fHXmQCzA9tZJ8d7WCBNMgMx1kf8lpDomRZyVNBkLZYbFr+qGz7cKhgXesDJhSpsh\n"
                                            "0XNcS1pupfOBPdWBfSu9Jc05GYKeLkuBMtj6i/NrrKNWMFQwHQYDVR0OBBYEFMXJ\n"
                                            "Affl1/+a53aWT2rs1O1AFMN0MB8GA1UdIwQYMBaAFEEjNyUM3knyAH9yl3Ko5Zj8\n"
                                            "KuscMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0EAwIDaAAwZQIwAe4Rk5oI\n"
                                            "v0W/fiSmTWdzexFDQGi/Shg8LUWo/MotX3owI/RFfyGXu5KYNExEUQQUAjEAydXB\n"
                                            "EBeV7Ik4g1chXeJBafpWtfzXgkxhjI1628PgH+E+03M5qj4OYNjRFBwr36fE\n"
                                            "-----END CERTIFICATE-----\n",
                                            "-----BEGIN CERTIFICATE-----\n"
                                            "MIIB+zCCAaKgAwIBAgIULJRalVvAMm9NpFlkzRyJanYHY/YwCgYIKoZIzj0EAwIw\n"
                                            "TTELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJXMRUwEwYDVQQKDAxTZW5zYXJ1IEdt\n"
                                            "YkgxGjAYBgNVBAMMEVNlbnNhcnUgUm9vdCBDQSA2MCAXDTIyMTExNTEyMjI0NFoY\n"
                                            "DzIwNzIxMjIxMTIyMjQ0WjBVMQswCQYDVQQGEwJERTELMAkGA1UECAwCQlcxFTAT\n"
                                            "BgNVBAoMDFNlbnNhcnUgR21iSDEiMCAGA1UEAwwZU2Vuc2FydSBJbnRlcm1lZGlh\n"
                                            "dGUgQ0EgNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHWaXukxB5Pu/d5ujQna\n"
                                            "XnzMXmGXl27LLokxnFuVEGRRgo/PnR2QrGKZtGOhvAiLPAs4CdDSd8/pFV3MGyXU\n"
                                            "QcKjVjBUMB0GA1UdDgQWBBRLW9sB3a998eiT1Sr7k2B3lTvkMDAfBgNVHSMEGDAW\n"
                                            "gBQFyfgQpvFXtgpc2nUrRtsMWMgjATASBgNVHRMBAf8ECDAGAQH/AgEAMAoGCCqG\n"
                                            "SM49BAMCA0cAMEQCIB8rkLMbuYA/kbALaW8EgFAtrEpMMUQMsfwBW2nXiG10AiA/\n"
                                            "41u/K08iw0+whUE9vnGXgaBbVTzhMKRAuyToEtB9Vg==\n"
                                            "-----END CERTIFICATE-----\n",
                                            "-----BEGIN CERTIFICATE-----\n"
                                            "MIIFiDCCA3CgAwIBAgIUOoE4A4S4Ou8tYFHfvsj8SaXY4aAwDQYJKoZIhvcNAQEL\n"
                                            "BQAwTTELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJXMRUwEwYDVQQKDAxTZW5zYXJ1\n"
                                            "IEdtYkgxGjAYBgNVBAMMEVNlbnNhcnUgUm9vdCBDQSA3MCAXDTIyMTExNTEyMjUy\n"
                                            "OVoYDzIwNzIxMjIxMTIyNTI5WjBVMQswCQYDVQQGEwJERTELMAkGA1UECAwCQlcx\n"
                                            "FTATBgNVBAoMDFNlbnNhcnUgR21iSDEiMCAGA1UEAwwZU2Vuc2FydSBJbnRlcm1l\n"
                                            "ZGlhdGUgQ0EgNzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMDqUmnZ\n"
                                            "Y/mPMtNQz+gGF5+uZwyHb3PB2c8U+rPITvB4iqirQpw2LFsPLCjTWQ5Y3teWJ7nY\n"
                                            "dLVKK45/+6l7tAFbzkplGqYERmBitTCnPFrfcOJ1uDVWnuXsRwRaoYjwsKS4k4Pu\n"
                                            "y8/YH/fISNAfUxfwVK6B6goAylyrvfrw+Kpskaw+qg43mX7L4zCFgnnZrLJB4wKX\n"
                                            "DLYvmXNzFRgffTPndSRiG1Y5RNKfQYpHpwh8yXJ0JtWa0O4mT/rzDcnBuvy3mDUq\n"
                                            "QVS5klb04QJPEOYArqfUkz+GXtmunf5Xi6Rf26Ias1nquku9+rxGE87nE0bK91eC\n"
                                            "qzGSFc6NiOWOPWdSgLrZwSdNv1PAOdlLLHQ16vgtT8B/woxQjiEMK/cu5ZQBgen2\n"
                                            "qo8uVVCrxazWekJqD7MUtCV2puWMi6PDCrxddfZfQ9D43yRrjRfrTunFQk0sDw9G\n"
                                            "HdKv9UTUdGJUa4dVBIMB01/rsRU1iz+iTOX+EB1IqUR0AAus7S0hJg9mUFHUVaSf\n"
                                            "2IjskQ6atoy0pfTfRDWWq/HikFL3/5VFk8ot/mW7wK2jOTYG/16UzQKiqEn/Igxd\n"
                                            "6F99zdI5xaXdLC6lTsWcAEpRyEz/y9qYaOaKZg1Ori159+XL79mcDzCpE+mzLYQi\n"
                                            "1wdgxuhDJpgrLsFtndi1oOdRiAxYghZ8QHPxAgMBAAGjVjBUMB0GA1UdDgQWBBQ5\n"
                                            "a24vtgnJ0whAHfR3Vs/lrK2kczAfBgNVHSMEGDAWgBTdMFy8CB9Aihlk4dvMuaxd\n"
                                            "pnvfdjASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqGSIb3DQEBCwUAA4ICAQCL22vA\n"
                                            "mx+9KV+dBezrtQ1vTjeEkRkhHYulQ25apnZ2SOWjC0eOiDyJXbqj/1CIwclKBTc0\n"
                                            "crEE1klTVXi47xKkPyHEiNDzjQLb19QAXA296owSJZlCf07K9wxSzG71tcEkxIcN\n"
                                            "uIUJPpp9IFWgt5Lf877swfh9VBSJbQ3K1aQy3Vv8GduEwhlpitOioBM/qctaU/mX\n"
                                            "+uutOtujqLRDJOPqc79RDOr9f56hXsnCmShUr6SynVBdLaD1xZTQeOZluJf21qQv\n"
                                            "fwCm8SA87c6PTEd9vKQmxnwJUKwerBaeNCN+hooIk3w4X+roXWWi8dbfwbnvyEoP\n"
                                            "FE42lZYAiuUmZZ+qIPZBdDOfBU6kggIXtou1ltAes45SDmlJVPVJu6e9UmlIn+rn\n"
                                            "QLJsjHEa9uqupR28p/s9fAJYRZTkqty1s7XWoM2Pp8yMBODI4Gtca59Vpfuqc/3/\n"
                                            "2HgAdIx/OcKhMkyCPLJSM/WjQVl06SvjXOcP8lfXRWHkFgvKMvhlLEYlAw6Afdqk\n"
                                            "F+xMr4HqYKmmECsHSPNui21AsBiwRbbS/3j9JnfQlcC6yaRBpPXIGvWtMhpYolck\n"
                                            "eIjix8UZrriWhI5L1/JJ28gvxYWbt1Zgq/1pBFwzUewYmx2OOzGKpWVajsKJMkoa\n"
                                            "yg1BUJrYJnF05rtOiruhBnFk9klVaFM65UNHvg==\n"
                                            "-----END CERTIFICATE-----\n",
                                            "-----BEGIN CERTIFICATE-----\n"
                                            "MIIFiDCCA3CgAwIBAgIUC2K05TuBq6+GIVLRHWrZekqnptEwDQYJKoZIhvcNAQEL\n"
                                            "BQAwTTELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJXMRUwEwYDVQQKDAxTZW5zYXJ1\n"
                                            "IEdtYkgxGjAYBgNVBAMMEVNlbnNhcnUgUm9vdCBDQSA4MCAXDTIyMTExNTEyMjYw\n"
                                            "NVoYDzIwNzIxMjIxMTIyNjA1WjBVMQswCQYDVQQGEwJERTELMAkGA1UECAwCQlcx\n"
                                            "FTATBgNVBAoMDFNlbnNhcnUgR21iSDEiMCAGA1UEAwwZU2Vuc2FydSBJbnRlcm1l\n"
                                            "ZGlhdGUgQ0EgODCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALe8Zv34\n"
                                            "Dn1tEUDCofUMAA2mvyEUAzZbvmFH9j66MAWwDuogaY2VQ36n9epAfAUnxEA2ycHi\n"
                                            "kl7PgTs8WdtAFUxbx9MANNuXp87zYmsfo9PQ54Qvafs9AOL8XNwLGlJzspxKXAu3\n"
                                            "1bZT13VnY4v2JesSN7C0npYEmLo4lRahbuLtPeBQvrpJbYZCp0EgCRJC+AWu0XP/\n"
                                            "UK3ACBiOUxH0A5wDExobaj+IREuKBHHtgwZUtKXYgzrRhjdj5ikY/bAgDnHTxp8l\n"
                                            "nk9l2RFLM4aza0gm+jQBpcfIU/rflSQWXIZJTTZKPktmNgKDU9Ujmd+F8xENo01I\n"
                                            "2ecfUJdeh0/REzAq9+Ew8B/CqEA4uJC+j0pvO8pOcSJYAbJ+X/OnsFYz4hFzKvkC\n"
                                            "ED1TqLA2p6T/u5XcKQj3A0LcsuhQv1FiHjKz1r/Eyconn7VMpN/qM/Ez9ZSADGCH\n"
                                            "Gf6PKqNbGCxUEdAsactsCOIiYO9iXJjDIxB8iiIYDAnA/ms+nsLGCbYpJFWpHRbk\n"
                                            "EVx9rTIcjwGu6FFD5ptD93yrlADcuTyD+F6Rr2m8myIvB4501LFoFu0JtFq+4Tji\n"
                                            "EO2xTDvNHDKv5t4VIi9+Sq0rrJvCnqddn4u2w2wkr5LzQCedn4mKVr2HfYtvLoQp\n"
                                            "BPhhlif9ZYl1hWgGcOUhAvdT5PiBzSUJHa77AgMBAAGjVjBUMB0GA1UdDgQWBBQT\n"
                                            "vQkna+czmFenVqkwzyu3QBmsFTAfBgNVHSMEGDAWgBQayTsNQl4en4Qpi85ky3v7\n"
                                            "ybO34zASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqGSIb3DQEBCwUAA4ICAQBVCn2J\n"
                                            "8WjjuhDTL6NZDDorsoXMwGdrCtNhSewP4dUEo30mwEPbzBncN/hMWFnwRH69Aw1P\n"
                                            "flyU0YyydLf1nHETsvng2WcICem2H+TB/q+wBMCslCdL34CN/Qvxg3kzEbJQYCkA\n"
                                            "vjo4cQurvrhBfTfvWghJq4lV7XTyGxdvZA07IBYfgtUjNajXXuQqArTlqfyROLPA\n"
                                            "WkOdTanoExVlJ42gAMHpun9CHq3QqPC5EleD0YNBRdZq8uBAsMZl4dpUQsfPV2wy\n"
                                            "OsuNWsTjFiX5YnBnAzzkqucYbLWkuQecFm5k4m6Dg/LV2p/77MAk0WRazsTNvi72\n"
                                            "QumWLfWidPH+nU6GyW38uvk/UbSCgqDl69ZUjaeAV84iYnsFHtSLR3919Ey02pXF\n"
                                            "zzfYzl4//EnaHEfhKAf5qj0fl5XpDB7tGClFKUWidR5IebH/+f7tBqhcnuJhFKaV\n"
                                            "hzwTyTHLdhcnCPN8Kso68oi20PX147LFC+pkKTxx8+Kj8Lme4RUDnoYxOoAhxt0O\n"
                                            "oEaaSCQ4kcNO2HetYyoeS5tIsdylhHlXgctJeohfYuaeQsj9hEreEjO8sY8JuBk6\n"
                                            "4QHgf61WEMqfxk5Eg62uTzmz5IsKVf7/tnKzeBxPI4kszn/78xodhae8peEP+rq6\n"
                                            "PmtuEWZV5I2OoGJldtf1ox6nFnD+Ewpr/HFt0g==\n"
                                            "-----END CERTIFICATE-----\n",
                                            "-----BEGIN CERTIFICATE-----\n"
                                            "MIIFiDCCA3CgAwIBAgIUHtwLMMzE1hapg12sqBaRsdgoG0AwDQYJKoZIhvcNAQEL\n"
                                            "BQAwTTELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJXMRUwEwYDVQQKDAxTZW5zYXJ1\n"
                                            "IEdtYkgxGjAYBgNVBAMMEVNlbnNhcnUgUm9vdCBDQSA5MCAXDTIyMTExNTEyMjYy\n"
                                            "NloYDzIwNzIxMjIxMTIyNjI2WjBVMQswCQYDVQQGEwJERTELMAkGA1UECAwCQlcx\n"
                                            "FTATBgNVBAoMDFNlbnNhcnUgR21iSDEiMCAGA1UEAwwZU2Vuc2FydSBJbnRlcm1l\n"
                                            "ZGlhdGUgQ0EgOTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOvw+p7Q\n"
                                            "RNx3aayIejDrMoT1+DDb4l8FrF4dZyznCcQpmw3/vOxq1vxaloLm6ODGQlGNDJ5t\n"
                                            "oLRnrARNliS3UMbNHDfU634JqyJC/AJk0CD7T4ZPROlOerpkY2VOnYgLEP+9JP0h\n"
                                            "OJnpcrrUIMycRGEXQu4VeNllnsW3JJP949CAbv44JPGABOdVB48T0flCom79ZXT0\n"
                                            "zbUTou7nl7YfJf52Tl7al1NO/K7Bmutd5shxvqwiHMd0wSXeQm3yDvKaKSc0nGNw\n"
                                            "lBKWIFSdV29+Jfv5Pim9y73HOI1uR+stnloJ23SvXbcbjWWUhID5dap1Poc2so9V\n"
                                            "7xsf51Yd7V1+hByKPgOd+CECaBVtNTKbdfO4nPVv4yBKqFq/5PUlct8E2EuC1eRn\n"
                                            "LXZNnPpQSjZ5n7cBQW14c82BUcfVE2tWb8l6szh3YbFXhFzhlteBWlc/maXtzs4G\n"
                                            "/o1taobNDU1BMntjYW79owWvf8Y4TPx1onymkBBy1Ih4+/5LF7k54zj5K0P9p2IH\n"
                                            "wWawUcULz43Nutc4vAK/cVyvnrZ8phwNIDksU6VAnzazq0Mwg1bvnksmV3fTMxtt\n"
                                            "XdKUwPdYcmRvQb8hMnNYd+g80SQSXf/BkZxvtWPwQ7eWpOxqZWtogCcZdYZ1LQ0l\n"
                                            "pPTYnHKgIVe7a6oSifU9kz3RIp0fzBXUTC9TAgMBAAGjVjBUMB0GA1UdDgQWBBQU\n"
                                            "pjSHo+e+kUvES78u6Vd5lL3rQTAfBgNVHSMEGDAWgBR5x9BONAqF4J1rNtwLZhCV\n"
                                            "bPA4djASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqGSIb3DQEBCwUAA4ICAQBXTgrt\n"
                                            "v4CEWLrSx8rrhPa9NdyMlsRrhlzyjYoFI1XdhvjGfhLzoMfQ1Gf6A1zhEp5yl07R\n"
                                            "4SsD5HRredMzyj/t0thdfb9Vg5zA+r53VVqU2OfcHFllB6P6SDHTcrlnkXqLQFN+\n"
                                            "IJdH6s5mDIPCiBrvf40IGC/12bD834twou/mLPiG94jKjCxwNXBH5m7oEVHBEX2L\n"
                                            "42whAn0iHygUFEA7NqzweyVuM4p4UHrG7ShN2SCXFDxiKkAXNyg48i+y1Sp49SoQ\n"
                                            "EgQmRvf2xl2e+8xBJFOEJqHlTOB25c8UsLIpJnZ3LDsEqjI5lPo27CCMLjAo1XKk\n"
                                            "bUqqXyxGoGvUSS+7j0DEdIuWdkhlud1doDcxcFVmWct5c1NnA9jWIGlpe8e6Q2I4\n"
                                            "8nzgQ6zmFwttQxy5PPbDpdyk82PrBUeLywPeSVBRxZRZ81BEXZYkA7o+UWI4NNQ3\n"
                                            "la6nERcEFSXycXQvicOE+JmwAzEZtSDAOQxrAlyyMIrBuGb6G1eT16jDFOhb/xAk\n"
                                            "bvzO5OkleivKm68xxxKgEIE8Dt9Ib+Zgg/48mxmWdCsJPlw+q9WV2Xk44nFewDDC\n"
                                            "U5z15V3NGT8O94U3G+vfMwZLJtpqHnsX/xSlELxhwnggfQFf3pAxxYUiE+fNBq8d\n"
                                            "ZQtc4bP+ptObf92ZzAGSYfHHBiErecqA1GEERg==\n"
                                            "-----END CERTIFICATE-----\n",
                                            "-----BEGIN CERTIFICATE-----\n"
                                            "MIIFijCCA3KgAwIBAgIURLGrGm1lKwR9ONosNfBq6gKuZeMwDQYJKoZIhvcNAQEL\n"
                                            "BQAwTjELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJXMRUwEwYDVQQKDAxTZW5zYXJ1\n"
                                            "IEdtYkgxGzAZBgNVBAMMElNlbnNhcnUgUm9vdCBDQSAxMDAgFw0yMjExMTUxMjI2\n"
                                            "NDlaGA8yMDcyMTIyMTEyMjY0OVowVjELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJX\n"
                                            "MRUwEwYDVQQKDAxTZW5zYXJ1IEdtYkgxIzAhBgNVBAMMGlNlbnNhcnUgSW50ZXJt\n"
                                            "ZWRpYXRlIENBIDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAz6mz\n"
                                            "PlP2aTNZvZNr623OEVvQtFrk/B+/SdI9Sr2ZcVrJFmYjxtiu8wUMySQ0yyMxxycr\n"
                                            "Kaqh3xcE+Sfalg5ZDanfONFvkrMuXhZSYjFrbY+84SZPGqikFU2jKEyzf9Ruu5ue\n"
                                            "/eqk0BDagMys+ghL8BaK7ig3eE1FG5TWBLPuQEyTTCKKp8OEFHGH79e+tM2G6e4v\n"
                                            "ecaCELNPffPPf69IN4cHWYRaktYQVPoOPZ0hr6JYZEhwF2Ho8EUEeuYlyEaYLi8r\n"
                                            "yWzwpK9MQDx7mJC/WT89Mcn7Hvrm73dDdy0XDzUZx4Ng9JNwST+eYLjjOlfEUsFP\n"
                                            "R9U8gcmIuuCGNXmPrgLQ4DQ2fq4olVoOWgxhGsNAh60yU7u1hz/0cMubpihGGWj6\n"
                                            "S0ojz0VmopAr+DEcrj2Iam3WrjyCQwTV/vUayGdxZeAImEvd9xKqsUUVU90Povun\n"
                                            "rlCCxG1PwxAlWDd9HINB6IB/FD9NEb87/sVAsa3qdNO9+onq0K+gs1aVyxkpr5RS\n"
                                            "H6RO1VxKva7L0J/FD8XldOZ9aWBBsIqQFqWGbId/mJJXo7CYtDr2OZoXg7TMaFFe\n"
                                            "rBlJVxvuJzXhct/tvlKOwXjev1kwZlughDmAe8rSKBkYczCeRGUaP0Cmjwi1T2/n\n"
                                            "iMBG4w9piTcd+q1PsH6bYklYXqFZCujSd3Dj44sCAwEAAaNWMFQwHQYDVR0OBBYE\n"
                                            "FPjYA9VUg/OAdlkMbkxmmaEfs5t5MB8GA1UdIwQYMBaAFG2V9upKs145h0vPetfY\n"
                                            "+1vHW/lmMBIGA1UdEwEB/wQIMAYBAf8CAQAwDQYJKoZIhvcNAQELBQADggIBADgw\n"
                                            "3mFNFyCfL79Aa9uc3gKa+QTyb9iESB3aUDb+SdjKpSzMeLQyqhFWnabLgRH8Z2Qv\n"
                                            "IMksqx9y1jJaItSjLWLOXssOcI3e1H9Sa+mRCm6QVqAjVm0JTFCC1QFLoAelzyFc\n"
                                            "x4J1ylwNlWNoB9gEcMCv+ihNjv4uwkxZrlQwryK4jfMHwPX5nVCsTtEVDP28ZvO2\n"
                                            "mbm2ubN24WgM+2FslTBcoH/xjxBOpHRnnY4b98YNhfqQyuh1XSBmF2bD6BGZ0D7v\n"
                                            "xAIdJGLO9rNU5eaxl7wa58xLKNgBNVpOefSJM0YiKHlm31yv4BlPu6B9u1JkbjwL\n"
                                            "HnTpBE94kHhdbSye5+H6puWstJnTHLA/kmukHNs/Hmvb78U/ZdRILj0zgGZGwSfg\n"
                                            "cA1WVSfUJE3qupgSBYYFFq9xhp2bo1g8cId5ms0yHmGcgVLYHLonpst8yM2USstG\n"
                                            "aw1aze97yuQNNGMLBdGxMqn7arHAEjghYigJC3jSg1hdZnqWW7V0fS0qJX5Gd1JA\n"
                                            "r44WxH1mbK24YTWxbwdLTuWAuszuE2uRe1BlrgZXIy+3yvKCtwulPF3OCJNzecIx\n"
                                            "HpP3m6AGv1KMkhqpamIJvBNI4YHgT4JjGu9T5c98mO6UsT1BQFDByGwuwtU+tnbs\n"
                                            "Ocr13HEArRL2Ljw8Lse6H04l158pdORh+/P9k2+q\n"
                                            "-----END CERTIFICATE-----\n",
                                            "-----BEGIN CERTIFICATE-----\n"
                                            "MIIFijCCA3KgAwIBAgIUDnb9OYg9/08mUi/t2dCfcZYUGLgwDQYJKoZIhvcNAQEL\n"
                                            "BQAwTjELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJXMRUwEwYDVQQKDAxTZW5zYXJ1\n"
                                            "IEdtYkgxGzAZBgNVBAMMElNlbnNhcnUgUm9vdCBDQSAxMTAgFw0yMjExMTUxMjI3\n"
                                            "MTVaGA8yMDcyMTIyMTEyMjcxNVowVjELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkJX\n"
                                            "MRUwEwYDVQQKDAxTZW5zYXJ1IEdtYkgxIzAhBgNVBAMMGlNlbnNhcnUgSW50ZXJt\n"
                                            "ZWRpYXRlIENBIDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA9k8j\n"
                                            "mJvFWfNeBadyLoG60t+SGIs34hAovWv1yp/plk1Y5cl5ba81+nXlPb3jNBsSU8tv\n"
                                            "/UMTq77EHVPHOhXWdQgkr/KLkzcoTrR05NB/ouqlZrBXEIh+MsIzWmv3RxC/aL5M\n"
                                            "m67Y2i8QYoYJsd4VkgJl2F4pS5Gs4bcakc48KdLiLG7vydGb7RtWGMagx1wEnm21\n"
                                            "k56phqJrfmBnvjU9sgSeH+jGbOIU3//c18Lbxmk5d9SLOUo1yYQvfXRaqXpMoL1u\n"
                                            "gJFtco0BR64zhkRN6mvNPJR/iahiCnaqUOOxV+MbUZ7qN1Gj+LU7UPg91/Mf1Bgj\n"
                                            "k6XczDo2KSd/mzHOXIo9/XPNVSxoXtmZTCLwznQC3Lorz0LoCCRjARPQT6juZZb9\n"
                                            "bKUh0IeAtQqCiRMw294UEXLPXRiBJ/cPV7jRx/PRRee0NCovIs4jn+xA3syreByK\n"
                                            "utT9f5AjETznaqOyWMJd7tBxyxSPOqMg6UxQ9r2GNtE/EvlooJTMchekyYiQk2Og\n"
                                            "intNseFhCV5tyfASEryjbOA7aByID1VtBNAr2nQe8w+Moj1aYyZWgz/4BovK6lr7\n"
                                            "+8HopiLpwwIy5HOzl6kggEn2VLm1O5PqHXO1hEDi245NeM62HtGBOfjoIhEgpiIz\n"
                                            "djb/a5OWTwhgcly7BHHmxVuy0EhK0JMDqnr7+HsCAwEAAaNWMFQwHQYDVR0OBBYE\n"
                                            "FLHUMIlBW2lw2GY9vxG2+OU00i6SMB8GA1UdIwQYMBaAFAWvEZak4phDBOwcgjTh\n"
                                            "M2SmqR+4MBIGA1UdEwEB/wQIMAYBAf8CAQAwDQYJKoZIhvcNAQELBQADggIBAL0w\n"
                                            "C6xVNvQi/t3ajSP4msywg1734TZqrD3nOMXKdNtfqMC7ykh2LxKfKJDhy6b+OxAu\n"
                                            "QejCHa2prlvyelu//ee0nNsH99rVHozh7fu3ERJI05OdyxR5TZo07P1vMXitUlhq\n"
                                            "cciSyKUr/jX79dKZKrlNl7Xcj7awa7B4erF4tzEV/SyxIw3dmsieVXHhQ0EnY2xf\n"
                                            "NGujt77YvM1lfbVIhFo+TQhsH8/VVYbFzMnOcqN5kYtHkEWpiS3KVeZ5IaD2HTxN\n"
                                            "ETDVQAY5yzu9YDnr3CKW8fhFrObzQOP2X4N2PMMTOoVXCydG7mtPPFAG6Yhq2bhA\n"
                                            "SCuYxcvKJPPrGNxoomNk264bfraKcoa5/hz547lAKsNdk1DqR8Ks+Vubm0Yz7+OY\n"
                                            "tNZH+pPOiG+9zsUrbDLF6FMUS9wrS00jolnDrIqH7YZaMxiK4TE08WZQ3KCZo6P9\n"
                                            "M/Bbro+PrpOhSaOpvhSClVbR629aISvQo2WnkcHS+q+AV/078Dztfz3i5EWJiWVl\n"
                                            "Nyo9/zWcfpOFKKb1/ugdsSB13vHLgZS5SvzGV+L3sqkKyYjiAtYriq0fH9963Aiv\n"
                                            "wi7CILEjVgqKvMMFjUHPOxPnVh/MuHAqjoAQhVp9ikPQRcTxtd7yi1zWpq7cehXY\n"
                                            "EoVc1F+vFX2tnd2FCotBFm0N2To6/zbNksl9RKSb\n"
                                            "-----END CERTIFICATE-----\n"};

void printHelp() {
  std::cout << "Usage: mellonbot [OPTIONS]" << std::endl << std::endl;
  std::cout
      << R"(mellonbot renews certificates signed by the Sensaru CA. Without options all certificates within the directory "/etc/mellon/" are renewed when necessary. The file names must be "<name>.crt" and "<name>.key". File permissions and owners are preserved. It is recommended to call mellonbot twice a day e. g. using cron.)"
      << std::endl << std::endl;
  std::cout << "OPTIONS:" << std::endl;
  std::cout << R"(  Option                  Meaning)" << std::endl;
  std::cout << R"(  -c [CERTIFICATE FILE]   Path to PEM encoded certificate. The file neeeds to be writeable for mellonbot when the certificate should be renewed.)" << std::endl;
  std::cout << R"(  -k [KEY FILE]           Path to PEM encoded private key file. Can be GPG-encrypted.)" << std::endl;
  std::cout << R"(  -f                      Force renewal even if it is unneeded)" << std::endl;
  std::cout << R"(  -h                      Show this help)" << std::endl;
  std::cout << R"(  -v                      Print program version)" << std::endl << std::endl;
  std::cout << R"(  Additional options      Meaning)" << std::endl;
  std::cout << R"(  -r [TOKEN]              Exchange token for certificate. Certificates are written to files specified by "-c" and "-k".)" << std::endl;
  std::cout << R"([ -t [COMMON NAME]        Create token for certificate. Requires "-c", "-k", "-s", "-e" and certificates with the necessary permissions. The private key has to be GPG-encrypted. ])"
            << std::endl;
  std::cout << R"([ -l [CSR FILE]           Sign CSR. Requires "-c", "-k", "-s" and certificates with the necessary permissions. The private key has to be GPG-encrypted. ])" << std::endl;
  std::cout
      << R"([ -m [CN]                 Create CSR using CN. If a JSON object is passed here, mellonbot validates the JSON and base64-encodes it for you. Requires "-c", "-k", "-s" and certificates with the necessary permissions. The private key has to be GPG-encrypted. ])"
      << std::endl;
  std::cout << R"([ -s [CERTIFICATE SLOT]   The certificate slot to use to create the certificate. Must match the ACL of the certificate's type, so this is not an arbitrary value. ])" << std::endl;
  std::cout << R"([ -e [DAYS]               The number of days the token is valid. The maximum is 365 days. ])" << std::endl;
  std::cout << std::endl;
}

int main(int argc, char *argv[]) {
  try {
    auto bl = std::make_shared<BaseLib::SharedObjects>();

    Operations operation = Operations::kRenew;
    bool forceRenewal = false;
    std::string token;
    std::string tokenCn;
    int64_t tokenValidity = 0;
    int32_t certificateSlot = -1;
    std::string certificateFile;
    std::string keyFile;
    std::string csrFile;
    std::string cn;

    int option = -1;
    while ((option = getopt(argc, argv, ":hfc:k:fr:t:s:e:l:m:")) != -1) {
      switch (option) {
        case 'h': {
          printHelp();
          exit(0);
        }
        case 'c': {
          certificateFile = std::string(optarg);
          break;
        }
        case 'k': {
          keyFile = std::string(optarg);
          break;
        }
        case 'f': {
          forceRenewal = true;
          break;
        }
        case 'r': {
          operation = Operations::kExchangeToken;
          token = std::string(optarg);
          break;
        }
        case 't': {
          operation = Operations::kCreateToken;
          tokenCn = std::string(optarg);
          break;
        }
        case 'e': {
          auto days = BaseLib::Math::getUnsignedNumber(std::string(optarg));
          if (days > 365) days = 365;
          tokenValidity = BaseLib::HelperFunctions::getTimeSeconds() + (days * 86400);
          break;
        }
        case 's': {
          certificateSlot = BaseLib::Math::getNumber(std::string(optarg));
          break;
        }
        case 'l': {
          operation = Operations::kSignCsr;
          csrFile = std::string(optarg);
          break;
        }
        case 'm': {
          operation = Operations::kCreateAndSignCsr;
          cn = std::string(optarg);
          break;
        }
        case 'v': {
          std::cout << "mellonbot version " << VERSION << std::endl;
          std::cout << "Copyright (c) 2022-2023 Sensaru GmbH" << std::endl << std::endl;
          exit(0);
        }
        case '?': {
          std::cerr << "Unknown option: " << (char) optopt << std::endl;
          printHelp();
          exit(1);
        }
      }
    }

    GnuTls gnuTls;

    if (operation == Operations::kExchangeToken) {
      if (certificateFile.empty() || keyFile.empty()) {
        std::cerr << "Please specify the certificate and key file to write to." << std::endl;
        exit(1);
      }

      BaseLib::HttpClient client(bl.get(), "mellon0r0c0.sensaru.net", 443, false, true, true, "", caCerts, "", "", "", std::make_shared<BaseLib::Security::SecureVector<uint8_t>>());
      client.setTimeout(600000);

      BaseLib::Http http;
      client.get("/api/v1/ca/token?token=" + token, http);

      if (http.getHeader().responseCode == 200) {
        auto content = http.getContent();
        std::string contentString(content.begin(), content.end());

        auto responseJson = BaseLib::Rpc::JsonDecoder::decode(contentString);
        auto responseIterator = responseJson->structValue->find("success");
        if (responseIterator == responseJson->structValue->end() || !responseIterator->second->booleanValue) {
          std::cerr << "Error fetching token information. Is the token valid?" << std::endl;
          exit(1);
        }
        responseIterator = responseJson->structValue->find("result");
        if (responseIterator == responseJson->structValue->end()) {
          std::cerr << "Response from server has no data." << std::endl;
          exit(1);
        }

        std::string tokenDn = responseIterator->second->stringValue;
        std::string csr;

        if (gnuTls.createPrivateKeyAndCsr(keyFile, tokenDn, csr, certificateSlot < 5 ? 512 : 256) != 0) {
          exit(1);
        }

        auto exchangeTokenData = std::make_shared<BaseLib::Variable>(BaseLib::VariableType::tStruct);
        exchangeTokenData->structValue->emplace("token", std::make_shared<BaseLib::Variable>(token));
        exchangeTokenData->structValue->emplace("csr", std::make_shared<BaseLib::Variable>(csr));

        std::string requestJson;
        BaseLib::Rpc::JsonEncoder::encode(exchangeTokenData, requestJson);

        client.post("/api/v1/ca/token", requestJson, http);

        if (http.getHeader().responseCode == 200) {
          content = http.getContent();
          contentString = std::string(content.begin(), content.end());

          responseJson = BaseLib::Rpc::JsonDecoder::decode(contentString);
          responseIterator = responseJson->structValue->find("success");
          if (responseIterator == responseJson->structValue->end() || !responseIterator->second->booleanValue) {
            std::cerr << "Error requesting certificate." << std::endl;
            exit(1);
          }
          responseIterator = responseJson->structValue->find("result");
          if (responseIterator == responseJson->structValue->end()) {
            std::cerr << "No certificate in response from server." << std::endl;
            exit(1);
          }
          std::string certificatePem = responseIterator->second->stringValue;
          auto newDn = gnuTls.getDnFromCertificate(certificatePem);

          if (newDn != tokenDn) {
            std::cerr << "New DN does not match old one." << std::endl;
            exit(1);
          }

          BaseLib::Io::writeFile(certificateFile, certificatePem);
        }
      }
    } else if (operation == Operations::kCreateToken) {
      if (certificateFile.empty() || !BaseLib::Io::fileExists(certificateFile)) {
        std::cerr << "Certificate file is not specified or does not exist." << std::endl;
        printHelp();
        exit(1);
      }

      if (keyFile.empty() || !BaseLib::Io::fileExists(keyFile)) {
        std::cerr << "Private key file is not specified or does not exist." << std::endl;
        printHelp();
        exit(1);
      }

      //{{{ Validations before loading private key
      try {
        auto json = BaseLib::Rpc::JsonDecoder::decode(tokenCn);
        auto typeIterator = json->structValue->find("type");
        if (typeIterator == json->structValue->end() || typeIterator->second->stringValue.empty()) {
          std::cerr << "Token's CN is invalid. \"type\" is missing." << std::endl;
          exit(1);
        }
      } catch (const std::exception &ex) {
        std::cerr << "Could not decode token's CN. It is not a valid JSON object." << std::endl;
        exit(1);
      }

      if (tokenValidity == 0) {
        std::cerr << "Please set the token validity." << std::endl;
        exit(1);
      }
      if (certificateSlot == -1) {
        std::cerr << "Please specify a certificate slot." << std::endl;
        exit(1);
      }
      //}}}

      bool keyIsEncrypted = false;
      auto keyData = gnuTls.readKeyFile(keyFile, keyIsEncrypted);
      if (!keyData) {
        exit(1);
      }

      if (!keyIsEncrypted) {
        std::cerr << "Unencrypted private keys are forbidden for token creation. Please encrypt the private key using GPG and delete the unencrypted file." << std::endl;
        exit(1);
      }

      auto certData = BaseLib::Io::getFileContent(certificateFile);
      BaseLib::HttpClient client(bl.get(), "mellon0r0c0.sensaru.net", 443, false, true, true, "", caCerts, "", certData, "", keyData);
      client.setTimeout(600000);

      auto createTokenData = std::make_shared<BaseLib::Variable>(BaseLib::VariableType::tStruct);
      createTokenData->structValue->emplace("cn", std::make_shared<BaseLib::Variable>(tokenCn));
      createTokenData->structValue->emplace("expirationTime", std::make_shared<BaseLib::Variable>(tokenValidity));
      createTokenData->structValue->emplace("certificateSlot", std::make_shared<BaseLib::Variable>(certificateSlot));

      std::string requestJson;
      BaseLib::Rpc::JsonEncoder::encode(createTokenData, requestJson);

      BaseLib::Http http;
      client.post("/api/v1/ca/token/create", requestJson, http);

      if (http.getHeader().responseCode == 200) {
        auto content = http.getContent();
        std::string contentString(content.begin(), content.end());

        auto responseJson = BaseLib::Rpc::JsonDecoder::decode(contentString);
        auto responseIterator = responseJson->structValue->find("success");
        if (responseIterator == responseJson->structValue->end() || !responseIterator->second->booleanValue) {
          std::cerr << "Error requesting new certificate" << std::endl;
          exit(1);
        }
        responseIterator = responseJson->structValue->find("result");
        if (responseIterator == responseJson->structValue->end()) {
          std::cerr << "No certificate in response from server" << std::endl;
          exit(1);
        }
        std::cout << responseIterator->second->stringValue << std::endl;
      } else {
        //Should be unreachable code.
        std::cerr << "Unknown error: HTTP code " << http.getHeader().responseCode << std::endl;
        exit(1);
      }
    } else if (operation == Operations::kSignCsr) {
      if (certificateFile.empty() || !BaseLib::Io::fileExists(certificateFile)) {
        std::cerr << "Certificate file is not specified or does not exist." << std::endl;
        printHelp();
        exit(1);
      }

      if (keyFile.empty() || !BaseLib::Io::fileExists(keyFile)) {
        std::cerr << "Private key file is not specified or does not exist." << std::endl;
        printHelp();
        exit(1);
      }

      if (csrFile.empty() || !BaseLib::Io::fileExists(csrFile)) {
        std::cerr << "CSR file is not specified or does not exist." << std::endl;
        printHelp();
        exit(1);
      }

      //{{{ Validations before loading private key
      if (certificateSlot == -1) {
        std::cerr << "Please specify a certificate slot." << std::endl;
        exit(1);
      }
      //}}}

      bool keyIsEncrypted = false;
      auto keyData = gnuTls.readKeyFile(keyFile, keyIsEncrypted);
      if (!keyData) {
        exit(1);
      }

      if (!keyIsEncrypted) {
        std::cerr << "Unencrypted private keys are forbidden for signing CSRs. Please encrypt the private key using GPG and delete the unencrypted file." << std::endl;
        exit(1);
      }

      auto certData = BaseLib::Io::getFileContent(certificateFile);
      BaseLib::HttpClient client(bl.get(), "mellon0r0c0.sensaru.net", 443, false, true, true, "", caCerts, "", certData, "", keyData);
      client.setTimeout(600000);

      auto csrData = BaseLib::Io::getFileContent(csrFile);

      auto signCsrData = std::make_shared<BaseLib::Variable>(BaseLib::VariableType::tStruct);
      signCsrData->structValue->emplace("csr", std::make_shared<BaseLib::Variable>(csrData));

      std::string requestJson;
      BaseLib::Rpc::JsonEncoder::encode(signCsrData, requestJson);

      BaseLib::Http http;
      client.post("/api/v1/ca/" + std::to_string(certificateSlot) + "/sign", requestJson, http);

      if (http.getHeader().responseCode == 200) {
        auto content = http.getContent();
        std::string contentString(content.begin(), content.end());

        auto responseJson = BaseLib::Rpc::JsonDecoder::decode(contentString);
        auto responseIterator = responseJson->structValue->find("success");
        if (responseIterator == responseJson->structValue->end() || !responseIterator->second->booleanValue) {
          std::cerr << "Error requesting new certificate" << std::endl;
          exit(1);
        }
        responseIterator = responseJson->structValue->find("result");
        if (responseIterator == responseJson->structValue->end()) {
          std::cerr << "No certificate in response from server" << std::endl;
          exit(1);
        }
        if ((unsigned)certificateSlot < sizeof(imCerts)) std::cout << responseIterator->second->stringValue << imCerts[certificateSlot] << std::endl;
      } else {
        //Should be unreachable code.
        std::cerr << "Unknown error: HTTP code " << http.getHeader().responseCode << std::endl;
        exit(1);
      }
    } else if (operation == Operations::kCreateAndSignCsr) {
      if (certificateFile.empty() || !BaseLib::Io::fileExists(certificateFile)) {
        std::cerr << "Certificate file is not specified or does not exist." << std::endl;
        printHelp();
        exit(1);
      }

      if (keyFile.empty() || !BaseLib::Io::fileExists(keyFile)) {
        std::cerr << "Private key file is not specified or does not exist." << std::endl;
        printHelp();
        exit(1);
      }

      if (cn.empty()) {
        std::cerr << "No CN specified." << std::endl;
        printHelp();
        exit(1);
      }

      //{{{ Validations before loading private key
      if (certificateSlot == -1) {
        std::cerr << "Please specify a certificate slot." << std::endl;
        exit(1);
      }
      //}}}

      std::string dn = "CN=";
      if (cn.front() == '{') {
        try {
          auto cn_struct = BaseLib::Rpc::JsonDecoder::decode(cn);
          std::string cn_base64;
          BaseLib::Base64::encode(BaseLib::Rpc::JsonEncoder::encode(cn_struct), cn_base64);
          dn.append(cn_base64);
        } catch (const BaseLib::Rpc::JsonDecoderException &ex) {
          std::cerr << "Could not decode CN JSON: " << ex.what() << std::endl;
          exit(1);
        }
      } else {
        dn.append(cn);
      }

      std::string private_key;
      std::string csr;
      if (gnuTls.createPrivateKeyAndCsrInMemory(dn, private_key, csr, certificateSlot < 5 ? 512 : 256) != 0) {
        std::cerr << "Could not generate private key or CSR." << std::endl;
        exit(1);
      }

      if (private_key.empty() || csr.empty()) {
        std::cerr << "Generated private key or CSR is empty." << std::endl;
        exit(1);
      }

      bool keyIsEncrypted = false;
      auto keyData = gnuTls.readKeyFile(keyFile, keyIsEncrypted);
      if (!keyData) {
        exit(1);
      }

      if (!keyIsEncrypted) {
        std::cerr << "Unencrypted private keys are forbidden for signing CSRs. Please encrypt the private key using GPG and delete the unencrypted file." << std::endl;
        exit(1);
      }

      std::cout << private_key << " " << std::endl;
      std::fill(private_key.begin(), private_key.end(), 0);

      auto certData = BaseLib::Io::getFileContent(certificateFile);
      BaseLib::HttpClient client(bl.get(), "mellon0r0c0.sensaru.net", 443, false, true, true, "", caCerts, "", certData, "", keyData);
      client.setTimeout(600000);

      auto signCsrData = std::make_shared<BaseLib::Variable>(BaseLib::VariableType::tStruct);
      signCsrData->structValue->emplace("csr", std::make_shared<BaseLib::Variable>(csr));

      std::string requestJson;
      BaseLib::Rpc::JsonEncoder::encode(signCsrData, requestJson);

      BaseLib::Http http;
      client.post("/api/v1/ca/" + std::to_string(certificateSlot) + "/sign", requestJson, http);

      if (http.getHeader().responseCode == 200) {
        auto content = http.getContent();
        std::string contentString(content.begin(), content.end());

        auto responseJson = BaseLib::Rpc::JsonDecoder::decode(contentString);
        auto responseIterator = responseJson->structValue->find("success");
        if (responseIterator == responseJson->structValue->end() || !responseIterator->second->booleanValue) {
          std::cerr << "Error requesting new certificate" << std::endl;
          exit(1);
        }
        responseIterator = responseJson->structValue->find("result");
        if (responseIterator == responseJson->structValue->end()) {
          std::cerr << "No certificate in response from server" << std::endl;
          exit(1);
        }
        if ((unsigned)certificateSlot < sizeof(imCerts)) std::cout << responseIterator->second->stringValue << imCerts[certificateSlot] << std::endl;
      } else {
        //Should be unreachable code.
        std::cerr << "Unknown error: HTTP code " << http.getHeader().responseCode << std::endl;
        exit(1);
      }
    } else if (operation == Operations::kRenew) {
      std::vector<std::pair<std::string, std::string>> certificateFiles;
      if (!certificateFile.empty() && !keyFile.empty()) {
        if (certificateFile.empty() || !BaseLib::Io::fileExists(certificateFile)) {
          std::cerr << "Certificate file is not specified or does not exist." << std::endl;
          printHelp();
          exit(1);
        }

        if (keyFile.empty() || !BaseLib::Io::fileExists(keyFile)) {
          std::cerr << "Private key file is not specified or does not exist." << std::endl;
          printHelp();
          exit(1);
        }

        certificateFiles.emplace_back(std::make_pair(certificateFile, keyFile));
      } else {
        forceRenewal = false;
        static const std::string certificatePath = "/etc/mellon/";
        auto files = bl->io.getFiles(certificatePath, false);
        certificateFiles.reserve(files.size() / 2);
        for (auto &file : files) {
          if (file.size() < 5) continue;
          if (file.compare(file.size() - 4, 4, ".crt") == 0) {
            auto prefix = file.substr(0, file.size() - 4);
            if (BaseLib::Io::fileExists(certificatePath + prefix + ".key")) {
              certificateFiles.emplace_back(std::make_pair(certificatePath + file, certificatePath + prefix + ".key"));
            }
          }
        }
      }

      bool error = false;
      for (auto &certificatePairFiles : certificateFiles) {
        GnuTls::CertificateInfo certificateInfo;
        std::shared_ptr<BaseLib::Security::SecureVector<uint8_t>> keyData;
        std::string csr;

        {
          if (gnuTls.getInfoFromCertificateFile(certificatePairFiles.first, certificateInfo) != 0) {
            error = true;
            continue;
          }

          auto currentTime = BaseLib::HelperFunctions::getTimeSeconds();
          if (certificateInfo.expirationTime < 0 || certificateInfo.expirationTime < currentTime) {
            std::cerr << certificatePairFiles.first << ": Certificate is expired. Expired certificates can't be renewed." << std::endl;
            error = true;
            continue;
          }

          //{{{ Validations before loading private key
          //Always continue when we are not renewing
          if (certificateInfo.issuerCn == "Sensaru Root CA 1") {
            if (certificateInfo.expirationTime - currentTime > 28800 && !forceRenewal) exit(0);
            certificateSlot = 0;
          } else if (certificateInfo.issuerCn == "Sensaru Root CA 2") {
            if (certificateInfo.expirationTime - currentTime > 2592000 && !forceRenewal) exit(0);
            certificateSlot = 1;
          } else if (certificateInfo.issuerCn == "Sensaru Root CA 3" ||
              certificateInfo.ibsCertificateType == "apartment") { //Exception for old apartment certificates
            if (certificateInfo.expirationTime - currentTime > 7776000 && !forceRenewal) exit(0);
            certificateSlot = 2;
          } else if (certificateInfo.issuerCn == "Sensaru Root CA 4") {
            if (certificateInfo.expirationTime - currentTime > 157680000 && !forceRenewal) exit(0);
            certificateSlot = 3;
          } else if (certificateInfo.issuerCn == "Sensaru Root CA 5") {
            if (certificateInfo.expirationTime - currentTime > 157680000 && !forceRenewal) exit(0);
            certificateSlot = 4;
          } else if (certificateInfo.issuerCn == "Sensaru Root CA 6") {
            if (certificateInfo.expirationTime - currentTime > 28800 && !forceRenewal) exit(0);
            certificateSlot = 5;
          } else if (certificateInfo.issuerCn == "Sensaru Root CA 7") {
            if (certificateInfo.expirationTime - currentTime > 2592000 && !forceRenewal) exit(0);
            certificateSlot = 6;
          } else if (certificateInfo.issuerCn == "Sensaru Root CA 8") {
            if (certificateInfo.expirationTime - currentTime > 7776000 && !forceRenewal) exit(0);
            certificateSlot = 7;
          } else if (certificateInfo.issuerCn == "Sensaru Root CA 9") {
            if (certificateInfo.expirationTime - currentTime > 157680000 && !forceRenewal) exit(0);
            certificateSlot = 8;
          } else if (certificateInfo.issuerCn == "Sensaru Root CA 10") {
            if (certificateInfo.expirationTime - currentTime > 157680000 && !forceRenewal) exit(0);
            certificateSlot = 9;
          } else {
            std::cerr << certificatePairFiles.first << ": Certificate has unknown issuer (" + certificateInfo.issuerCn + ")." << std::endl;
            error = true;
            continue;
          }
          //}}}

          bool keyIsEncrypted = false;
          keyData = gnuTls.readKeyFile(certificatePairFiles.second, keyIsEncrypted);
          if (!keyData) {
            error = true;
            continue;
          }

          if (gnuTls.createCsr(keyData, certificateInfo.dn, csr) != 0) {
            error = true;
            continue;
          }
        }

        auto certData = BaseLib::Io::getFileContent(certificatePairFiles.first);
        BaseLib::HttpClient client(bl.get(), "mellon0r0c0.sensaru.net", 443, false, true, true, "", caCerts, "", certData, "", keyData);
        client.setTimeout(600000);

        auto signCsrData = std::make_shared<BaseLib::Variable>(BaseLib::VariableType::tStruct);
        signCsrData->structValue->emplace("csr", std::make_shared<BaseLib::Variable>(csr));

        std::string requestJson;
        BaseLib::Rpc::JsonEncoder::encode(signCsrData, requestJson);

        BaseLib::Http http;
        client.post("/api/v1/ca/" + std::to_string(certificateSlot) + "/sign", requestJson, http);

        if (http.getHeader().responseCode == 200) {
          auto content = http.getContent();
          std::string contentString(content.begin(), content.end());

          auto responseJson = BaseLib::Rpc::JsonDecoder::decode(contentString);
          auto responseIterator = responseJson->structValue->find("success");
          if (responseIterator == responseJson->structValue->end() || !responseIterator->second->booleanValue) {
            std::cerr << certificatePairFiles.first << ": Error requesting new certificate" << std::endl;
            error = true;
            continue;
          }
          responseIterator = responseJson->structValue->find("result");
          if (responseIterator == responseJson->structValue->end()) {
            std::cerr << certificatePairFiles.first << ": No certificate in response from server" << std::endl;
            error = true;
            continue;
          }
          std::string certificatePem = responseIterator->second->stringValue + ((unsigned)certificateSlot < sizeof(imCerts) ? imCerts[certificateSlot] : "");

          auto newDn = gnuTls.getDnFromCertificate(certificatePem);

          if (newDn.empty() || newDn != certificateInfo.dn) {
            std::cerr << certificatePairFiles.first << ": New DN does not match old one." << std::endl;
            error = true;
            continue;
          }

          BaseLib::Io::writeFile(certificatePairFiles.first, certificatePem);
        } else {
          //Should be unreachable code.
          std::cerr << "Unknown error: HTTP code " << http.getHeader().responseCode << std::endl;
          error = true;
          continue;
        }
      }

      if (!error) return 0;
    }

    return 0;
  }
  catch (const std::exception &ex) {
    std::cerr << ex.what() << std::endl;
  }
  return 1;
}