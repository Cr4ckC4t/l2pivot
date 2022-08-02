#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

/* tap */
#include <sys/ioctl.h> // ioctl
#include <net/if.h> // ifreq
#include <linux/if_tun.h> // IFF_TAP
#include <fcntl.h> // open
#include <unistd.h> // close

/* socket */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* interface */
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>

#define SILENT_EXEC // surpress output when executing commands

/* customize your tunnel */
#define UDP_PORT 5535			// UDP port for the tunnel
#define BR_IF_NAME "br0p"		// Bridge interface name
#define SPOOF_MAC "aa:aa:aa:cc:cc:cc"	// MAC address of the client TAP

#define MTU 65507 // maximum transmission unit for the tunnel (UDP)
/* random 65507 characters key for "encryption" */
#define KEY "f~Pq25GHyJieV&Y3^ScVzz-Mq@w924XMQ1OJbSXt4NMz3hbS%OnYL%hZH9zft^5ho5JxS#jsj7CX1rznfjU8^eyOglylML^wu%9LVkbHDG0sqvGadXHd*hRQEaE0Y9Zt&WbEvRNv4LD0wQ_vXun%H@&cALlYiiXotfM1B1_-vkTYJXDcS6Nzd&CquNAia-Yc0a@Rx&CuTS-K$O&6Bcf@kr-ol@6hKTKkgJDbA$@5fkUDn7aUE#!Gk%9_pvl-vSqkuDnu%haCXwl%ycTM7ARnaREIPHE0C$0IjaG#zV_~rbiYTB2oGXoHp#9XrxOSzI_VaSG!4yFUBRqnlMK4h@$&SwrfbS0#Lix%Eleg^0c^qg69Q^&#s&9uGxkyhMk2Z73Yeh3hS-^oDBckPT*1qAs_!pC9jsdQ0nxfT*z-MK3bcgyZCfS@dgSauvUI-y&bOd4Skka#gu_aOrlC&Qam@Ph_jZjsMKyFuEi7y0wF2N4vHijue4mlH&45JBb@GjOqu46yh8Ixo7RXE7DkK!cKpgm574IN1ML9cJ9Fpx*b0EOBTY*0ftzuXmgKwiSz1tBMcqoO8suWZ^qCv3m~pD$4eESDw8ykViC_E4&W5hE*bifG&xs$uVZBlfjo9aE*OG1jguos6w_&a8a%upn*WkhNkm7c$NbE^a&c4m%nRTzJ_gzpjz4Qnp4Fe6@FSRTM3cViLmE-vZv0qyGI^F3T9P0KVvaMplr0oCOdbwtZ_5^u&x0F*Y09l5&6QdxW9dMQmxn6HaTlURBMAhUA~xwNEhyWvhwgUdCRw4~omNBpK6gFFKgWszhYlq!AH^T&^@ZV4JVHE6x2YHtl9Q^YYYGyWmw$^jHiQYVfM3oyLZM8w2*8F4J9Ls-eKe4wv!Y*kp7fGc0r4YKKAHsb@Bn6$X#3_6OtVco~umXQJtA6-4F95-RT2BDgmdnz6yl1AMhexs!ywICUJ-O-k&L$rKPjw-pRqVE6rF&#UG%5P2f3BhG8gXB-%^h~pUYY06@Kr3hZdcUwsVfOK1b*77RFmbh2_lVXM4-r$H4!S5bDhk0f0QEU7mVQ_@7E7i5xd-o-4BcUlM63jwF%AU$#cn1f!Se2pSRuePzPh1j&ORs~2YQNo0FexDRjywQeGq-tY@sR6YD7h*^h_vQlZbjfqukdZFE~cwyK#RPwVwwb4MXpMQUf$%8sRFZ&g8f~oJj7NhR!i0Waa!~%LKLkwu0gDYKf_pnjOMcGyXhYGkt^7h2SM4Y2u2OQbS~MWuIbRyaZ&Ps5Gw0Z~z2PYwHqpLfZOvIvUpCprO1&DD0Ykpg*#pYVWLBR_vGSj-^FShOY$MtBqR^6dzqY6^o2yl1p4V%BawwBanHUBF3E~vWF7aHAwM7_b0tm@H*as1oPZj78lh3x0ArJliTdyr1Dm2nI*gn^QJ6H!qBX3RAmUzJmOvqNSOdtCiO69C4gX%tX3otv1wzjPoo8YkQt$V#hve@p24IaN@ntuiWoYQ~kQEpYuWI~H7~@%ZM#B!qQXE_ZE9bA7lsXxixdgD~vaKn^dEaC#uQl-dQYtQlRq-~rDYa~!jnr~K0~XAf!VicM4zfhNdOu8ygRnTYvFcS6JH_AZ3qato0kKv_YZo$!nruOqJHllZUDhJh0Ba#m5ib0c6E3u*6YczF1G4A#BTjgB^*i$Wt*0$Z92vj!M$iQ&LCckF2!pK8m2HHg#xEnMiavdPx2FbBi6pFeLaw~vxlZmyWsMN9tHO1u@^b-^vuadIBGQQ9P4xbVPfxd#1&i-b8zdB%OXNMTvc!36CQNH3zXQ-yOSD-z68n_ewXbx&6@jz0z1R$2z3TE~zUtnQhdjIe@6l~0v~aie6&8q0l~kK&xPju5ALg4yvw%tmk60KrhfZ2JQTmdIS1Y!p4UE@DacS0bZ#ylPhFg@2gCUm#$#kbxj!n~$*%fzR6aFA&Rl&-D0oNVEh7~E6rJIHE&f65*hUXE5qn~%DNgR6Wa6lDaRp9BzDT56eT2hqWVN&A77_67ZwNB#@-AVMO9nIS$E0KuS6q84OOKpDZEzfje_c8NM%UuIZ-oB#iI2ltD96!3o!4gNZgJVbIY$5JNuqkwZv$Ylp%46_*Ddn@#o2yEx&spAfHcV$^yuN*g#3Js~z*Mt*50tS4%CLgIWRw1tW9qehg*h3F%a_0mkQ6JeO1axurgM6zhSmu#~&V0Ped3uQn@pQVS#PthYcsnMu_a6n7Ty08qt5^#VI4lx&aYApgnKF0VMiv#-VKbg2_%ADoKehqWiULFMVjYOL--R$oQzCxCn@x@4bUtvkO077Bphfc1_@L4_&fMl5i!8KxPVIldsr5I_ut1Dvx^KtNRegCMp0upskv%VMk6lEs4ZOrqF-LBofWQxCpJ4VTT6KZzpGLuV^rFyUqP_6Nlk~M27Uf%DwBJsrKONur#6OwDL6%iSBlKv8PwpQpcZ6zHLhL-mx~1CqK#XSn3l^ct%5v&g0xH^c3xIFL!u7iJJoikp1!d^qt!dOa95iX6c98*-Vlbg3_Q^p0QwyqxS58QQLw^VFT3jZ#Gm_Qx0GtbW$SnGiJ6*a$@YKEhVudRB#EA^Wf_A9PjdU*kokwn~*1MdsDTCOXU~tOyEB!zvq*vIflh9ZwEiLFH&SDj04&Pnj1ZjeohIyBR$L69zRD9PNc12pOus3~SrQx8To#z6mx%RI0lhcFU21crJ4TBcvzsb&#Zda*P0zYWVT8@N_xWgxEm4VYh~4aRyqUBtnkgfvH*$v0y6h52S2#r2^egdncll_QWOgBZR$0w-*jf_5UlX6@q!n@O3k^W0By9mDWMZ%pXZdwuZGTqYtS$t-$OKVhszjbldMXgk#vCNbu#J5J!ikuR#GBdk7OQSwqZBXjNIEKLut0G0_3AotD@f7bDMO&EivcmelKnfetx%CWnyMOT6AJHy0sAxEXQ-2@yfmgM%k47g&qqP5Du3vSXMCdj9f2GFN3KwGahAgyf-THco2kgn!UKUsHQ62u5i_#5URs6qv@&_%LsYTiQxHZv1T~mA_xD_bLa5^Y*%-PcqA5fzyMQFgoxclcMBWgBO62HQocf2vWa9Nkikaa6JlB%41h01mr~liA5N@hVcQBDsnR#C3%885Q2pNtVJtkN6URkBpu6B@*%~~C0x0o2~2f#*9FHhUy@wR*l1MSuKDqDBuFe%EY@n9IlkHxnBmO_LNjqOL_hF#8Mz#MbvV_mhsn4&~5y9LxDB0pQIDdPvwH*MSMJX9O0tdUkMYTSpB#cQkn1wj_jNXp9bSLZ&$ldXspmjgQ-m%lnWd~a9Yc1bN4jMhWiNwOiLjyjv~GQRmSs!1O78lggr7J%ac5HJ7URg0#4@l7#ro2cn%6HsqgktJgkrTsEKAsBl-KAkwh3#msMLg&C&HBM0@pR6iVg6zU$eB*Lsroz2Ypk&8aam*#j%i*r~Gb2OnO66JNF1cT@0r%#PwCTe_#Y2jBXMFVYi9A7jp!E0#ZgsIomEx!E@bBfYoHl!ERIK-E3WLq~mfEGhdym2aHN@Tn1RGJjCWv5y^_D~D2_r^T~1PDd6rVc_69Bu&@RQ-w-4RG28stHkOURbwQ~$@9nBT7cVYXE3s4O&SlUfwgsQ&qxn&3Fq8!rKECJ~Rb4U_EB#4URNoPNbFXTTy%f5u9b#r^jrT_UgAh0PwO_cM_iKUoKdMMLAnGCfXiP3Oq_TfDJr7MVu0ImB5hzlZuReW!MOfI$mmtk9R6#fq_u5j2Hnv9L@edpiSPUeOor4KPUSNiS#b~p^kpPqvmEi2Bu&H-5moy1r5OHyg4tNAah~eP7%gPp35RgZKB_TWFcmZfWLBuQb@-ETUbP^FDel2fGsvkQ9NOlO2!cb-VBfQ7O^A^DE2kN5XHNyQQU6@fMD@711Zc@x!HHH-Uy43uF^ufyY6bUNiaiSPq9qw8auu5&5kRP2n^4p%tBB6fjYRjfDp8-YMKxLfPjzF#p-dLv~f@DB8wwMgO*0PA2edgP9jYsqA^_bATq6h8#uGmbetbfR&HH9#7O$-d6jpjEO52Jt&QhN~-@AQwtUz5y!^XXba&YZkXvsCY_eRC#eCTwW6Zcv@7yLVOFpqElj44vGT8$D4mc6~Q1x6h*6G8txJA*up2dy-vGhJIA-~OeeRR8*bUx5~~d4sRrNYLnjSJr#SfXxiK9n#^AK#CJIT3KUz9$tRb!0Bwfc!HSsbO4LHv*rjGie78Oekw9e0^yr1%CiujS9d^y~aNMVySeoI%NXd7mxy*A0AAwSgLtHwpmjPJ8p5ddLEgWmib~nQHu$R$X*uFKlWVHsaYKoi_54_t1z_13%t4W7bE7hNSBN$XJr0l5BEP@Fja4P_XJ#UedaeI0&9Rz$uFpQX&rU9G1BH&UG%2bUPKMj$MNtZwal-ipiv#40eiTu@DuPGjLCDGy0J5p!QswLVlNkP4!VAsi$UCZJqV!!WuokFa6IRj$DT6DhDe_tFl@pKJdd1h8Ewk@n^Tu_aYpH_dJppg960d9x0-Lj_GmQhHlGsBi~tYdChxqM@iA4HNm0VirubQ8v3gJ**k1r0EzEO6velMTiBDNZT_o4^Jzbbgw%GACRY*%v8et9qkHeX$dy7$XDDGXt0^60p18y21zq5WT&T%1Xm79M11ypjLnHuEeHDP*7q^_kBkwbgVbkep2OsRks^bPnRrbWJS_WWnrv@FOTleSHLOTaeI!_~CTp$FuRzJUlIEt%xwz#e2zK#j7CGtW$O5VxtqG-AC0PRw6j6PKYh3jx04CbkdAaSj^-J9nhItZ7KaSQb!GeH^@ELY#*O6&qI^@GVSgWKyK%zUhpk~fpY~*156tWHe#6F9iJ3!b9&!!-*m*-%Hcu$YUspUVnZGr9_%tHLj1KL_J9iIveCDkfuLQyOZkuMA8Psj2ZPu~QtZbjt1yMjwdAEF42xJ7nf0OP!^%C$fpdFrX-urneyaAock&WEuBAp!#2u~OsrN0HWK4r5mjEQHCpz#uHssS_Qq7bbqnS54oGTVfD0-D%-RPQJ&^MNl%9O!s@@vVOK-yRAbbD*uM1UqzcAwoWTzAO_V3ez4G_C0E9lEdr6v3p9A*GQfinh_4EFeM1%RJxIhq^wqZRL*!ra6vP1%cF6wgl1mBn_hVfmG5wir~q-iPZCqpWeR*veJ54n5#w6l!reup!TT_gBQMW8fNn1%Ir32HgjDk_e22FkJU9T&PYjv3I3gH1lfYachN75_UxTq5%j$3Q0SSv@9nnKq1VjMuWkpgZclDFgU-if@r0-7a9OamkV3xqFgOgSsGtH5P*7gI-0NnPot~W-~kwWZVt2I_abNx*tfdW6lp#QHsaPd$AFxgLnHI09~WK%FtqzeB#08yR0xOUlc53XS$z*fj#Nn^Ara8UM@Z9X1VinAEfYBO#P^^-~ZhR2q!nxUhu3LNU*BQyXloiUHG9PWYKD~xsOW-uHLmZsmbk%-bTETuywD0%IUpe9!eh#vvlkfsbiaq99RkR$57BwiOY425o1CN#E&9A-i!w~EutC^0viduonL%Km1E@duE_!7Ubyobm7$56YlAf0-6NRPHocDQH&d1C8zW*tzxk@8r54&%jLg1I9JF3@ZJF@w%E$QRD#5G2N6QPs^S^U~9IRLmBEO~@MqcqqB7NWN6$LoImmlSV64Xoi08$A7v61a&~wG8bpi*Dq^YEGvuJ@j5a7oc^5oTF3H1%BuIlUMlxHoz4ZEGn#do06vG&y!XWe3DsvhvSJcT&0f2%LwzP52we6IY8HTrYhu!TSpKBTHofs4UuGZP4a1C$&!I#hhvdpntZbir7lF*~p!IdnY07BH_Jr*4iAyn_D3ZvNG4l%nJBS%@~JH_A51zDzDe43UlpIeXZ^tHp#oMjPEhxUan~IO6KZa9T11yoUMS1JWPI_~TMWaI-$Un&Tr^K%TSG-El2#hIboHDyDy#$VFfRj!G9R8LW$!3s&wAODdH4hzr@MO2gJDb5mEklKcmnTE7A*qPfPvJFUp0#mYS@TYG7QtS71hrF@hJcLc@V^L$1WbCgOYW1Y!y2Of!dz5336Zr#OqK1JyZEXThEvvvc@l-I8O9N@DAWU#sOW0Y2x!L0$-gACJF#hB^p216ygdu989!vLKMqT5it-N&A9t#OWA9cnaF#yzd$hbt&o2&&&vY7wAOWGkDkxkapwMUDo1GQ9@tOts$M0J6YS#tz0xKE&s1jatG5cGVDRdsHysfcB@Nh@-fmSbJFhZgGBcD$vBdRHqF&RlS8jELczn8anM0swM8x@W9n&55wjv0hgU&xpXI7O5PoCV3UiXj%0rXgOjoh^^1mC2cb645TYvuvE6RFwzSfDGGenl4Yk3O*mVvj*~ZboIj-MdTo1$Pv!0P4EKeKPJ1pfO8FgC@TifSND~FFNij#%qq^X92W5G5WjXk!brtik!dtDNpofK@Z!aEgLl$~aI#BYDDnS&i3eyiyP&D$jSTKwOvz4zA@ob9jeTa^9D4UNtX4SMsw^-bk7$*txi2IGw*FNlQx66ud7kx!O8l&XaPgiJV5fUX*BMe707SW!YOXxm-Aw~cAiOHdJ2Qutty8Tgd$&BG*zfTrHsxoi6bm@diY@o8rN9BACjDgR&LudE^j@HzgOybTrKyU6ciEy7^XNG7xJ^vz4m-3mhMInI0QqhEkLBf!WPsR*35HSH0qE_uoym~WHm#pNqKhCLZht&Anh88OOUryyhwIZkOAT7wC%Qr8sjzXX7VZyI*wy3$*^@1VPG-hJ%*KcZWBEDAm^wnA3yxQ-^WyfWV5A8rdL&-djpHdSR@H~4UYE3TuN~nMQVIZ9G2J0nhGPggX51domW6k@@F*yN3kwoFouDwEPzTd8@ql3mX@fo2TFD$Et*CPLkQ!KLuNW_8^q@x&F%za2Yo^5yF^GHMf&hhQU3D#x2wPPZ1IZRF8apzQDj*TE&MqEC4GI2@dTcMIRpWc0Spb#aULK%#po1&uB!XNE#2dX$!yZLfy0Nb2jG0q1#HtjnH$3&fl-$h%x2ml4Pe3JgkBv#~^dJUVHhlb0waq2vuaA@afpU$2A^YeQk9jQHWonmaHfg%*5^oO-L*dNP%S1uATRpnLikWVkg~MfUdyy81zw*pNVtM#JQ_XS5UVKqy8d7vp6p6q#Dv-!&tuW$#bY@E6n7W2K5oDZ$0nQ!ZPfZuQKEv9ldfqvh-jUlFO&PqBCybyA#L$FlKLJil$A*0eTh_3K%BmwW7XLg0BbOGY^7qfRo2*J0XPng&Hq3$vInh2x#Tb0c5xay0eJFv6Mmc8waXeSeJX!X7xXiR&V_-AY*-i#^TU7mK%lo%bxCYN@RP!RH~IYCt@1ea59o!uoalTpkhelBRs_%Tsx*Qw~jH_aBpan&oGxiNvEj$0Z$ugJ@ccY364G13^irVPh86izfZb#__ybwffJVQOA9rLJVV@bQmUaNRWirXpf5enbEqPS*TCqvfa6-D6U_@Xm4dNVx~Z&aO!^Fnkxq*M4UE$kc7E@54xb1F!^VhlUPMCLpU1$^P9Yr_Ec$~_BO#2o1N%W2Bsr~V2uGiR*Bzw^elPW36SLt!P%CMBU8fFVIhs2!u-~Y9*yoS8~wpPvHspEa!t8uEOuaUE$OB5dQMJMcZi1nm7SRg3SOi7Am_02JTZRt7P5_A_^R@3uSbKSG%Wh_WxUI~w-2PQ4usut8xk_Ck6f!m9gSc*tyx#^UUZ0MygHmx6nrfLGH7JNqPzl%s#w%QtYajhhy0ltJJXdvj3ZNN9uwsH%!Szu-NhLhS_v~E@fQT@hll1AMbv_3tnu1!BZc@kr#2UbpP-oYzX~l##kEudna91O^vRwSInluV#9g7T5$-vbAiAInu5v4l~^q84Qw*ovbn*du1S5~dG6t3tXIhbvmykEs9&SN5PTde0~PQz~tB969gh_ARAd-Y*m8gHslozl7^-hSF77p~*AwQoIU^yH&R*y~r9FVG1DoP-kBZqhKRTB8bhcPFUT&B#I_Lth&v4-JOe4~E9NZKW%l2~$L6t~q3Ye5eGBJueJy6hJ1D_SuKZE#Pwr%sqiDenJ!zsJ5&m6wI5NqikR9~UejPobCy0jlA@Q6QKDmhUG&O-Bx8BLWXr@OW0Sz2MGBM3VNUbf#jSlppaFPq^4^Q@6~t_XprXDNSp#ChIlZE6wP%MT8zrkSP^TK*-BH%cLsEskoEIi6BD6Aw-MBb&E^gJaY9msTac8g77AIQqrT_lS7JF%irpTo8oy2jAtgNZVqoOrRqzgBHdkh7~rSX~9o7zTqhy3rc!3Y7&vVPNYS%225U6d8VxNd7~fkiKr1VQ%n6hN*~c%320aKw$YEJGlg3EmD2UX3Wj~qzjvQJAEwb_PW2x_Ct8UV4NNC5m_sijQ$Wi12jhQ455doj#mZ2iyf05a#pg!M%p9jX09Jgx7_vWzTMgxos7Kn_PJ#00&a_M8dx$y0H!%GNv*JPdMHGVbHxl9lZi3*XbYFS%%NES0%BqSXbI%XLl^!j2TT1GG^iatwLC4%q8fJR9pNmOYO@XBjGGCPFZ*X1Uo3dRc7AD8i&BrXbyiJ_Qx0kI7vs5q8Vj4U^%jD#aNGwkh3Lkk4mnpd*igTlFowE6Zzt9B98JEY^N*JUfRc0ltU*UpGvm4dDjKX5LpR2d%yE@NKaZYsAZ7wnAMk#J8F$qA9rDzbxpe3hoiLhpPB~I#POE7!c@9&Q%^A-hYVf@xTl$EBKfZIg-#7el%dO^-gs1pz5!mq7q#RylHt^%8p4Ds&YOTfQkbjKC9ADE0PL2^V0jb_#u8WSOu2ik^@U&2zGUl^j7pZzvZ*vDpATLgxi_GVF!QnL~gr6MNJ-#pFx~1ezBL*p*qn8Z#67Hm%8A_OiL&cDBswaV*5qCNE~@UJH%o85*ny%^9ff6s~Ntcwg2WiRtwD!*1JxhRlBB^KUuC#g81#xKlZWf$c*Hkqm5k^Kr1kSAat*^2mrrHFPynTjUuquKwX9#7o084PdzC3kWV#EKK8WZcn9unFnOdw#8WdTp6~to2AetsUlba7u^4uZCqt5FYi7eV^2dyz-lPHdMdUgAq5cW#O8tbVQNdgRvMA8TZGt8x^mb&FHFIo#!&qnW#yC@MK8fUi1iDLIOaCigyf9k@GPSYmNj*v8aj-ig1x96Je^IPC1O9tY6#ccl9eF_o3X*LCZ!xNTM5x1WrXQeWrZ*8FLZd5&AVST5HEmd0_-2y05EQ08Dc1M6iUZNCH#ke*58Vs!2wxE&TK!!*mvdnR3H7CCzY&qMPSScsr*K&P*Q!B0@fF#5CqexFpsw&Fuib$W-WCFE^#in%lyW$qqm5Ngp-U~db4BYe$$NwL#nE#AVDFWIMn84!38WW1Mc%QAiMWD0MnBzX^XBNGFlhpOakIj7gRureP2%zP&ksr3b*gFtss9%JlCfySwccZjK1QMHSAnOvgYolfod9pILBQ#u%-cWp8qC7NhpR1^!gLpJtAHYb9be!0iUQdodotaIYwr~pLI0BqweUv03olRxk3~BUhbyldvlIIiB#4*a26d!iFB!~oyWBIY2jtqx4e%P&D5ISe8DTm0kf*Y_$g~NdGReZTEwajHwg1t5uElsQlaQ10M8bELL8GYFotGpH1DL0T#hrDrIIl42sxMIlA~$CXh7x*bm!XEjOJzb9&PEr0X-BcCmu6dC&2f6O3r852RZWRg7K&Dv0Js8~OfzYiL!Du4n$Qx#1n^p^EZGG4FXx~&malpjeeisIHrxHr5!9@cyiTF0aC8cz*X5vFb~!xvVi#V2j#GlRu#x@C6t9F!7&_LQ$RFDjtSQeYjRYjGzEskpFD_rfCp7mI0!!3k~5Zi_gEt9-w0s-RIG1GAX_o1#xlb!E4TyK8UAu~6pzOOs1G-bIrBesGI47hMa6$XJl5uvFQvD8ARDNk4E9sN66Wo1a!V6YGLBiqpnhA1el%^2ViGQml5S4nWEQIVnS&Vfy2ZLt20@vIsFvBTBSVDJ71%MpX^2QqJOQDcY%FqcOueDG9j9vQCBKoEXf4Mf-Y6iwJl6%Wt4EIQn3LBL~MTrS_sQ30WoZ*v4OsTgViUQR$5TZio^M$nIu!#vo7n5d96kusPE@Pk*w7AnAOuYoklcg*dhPIv@cP0R_BKLcAwD2wr$LbrF_ZKcb2&iDT98SKcV8kHp2G2I6ls6BId4CO*5l-Gng_tlUakiIqwUhZZUbu#4wl^SRKzLLnj^d9aUT!Fp64qqI!s3klIt!^f#R5Ghq78l8PPlwMRS@N@^$lZmt~fGJltrc-yZrFXAr75x4-BHtp2g9Rm$BPMU5yuT&8PR6HYY_k-VoB60BCARyRW$wW$^#^SNeyBh-BBKumJIlcyfObK9b&v#_&1_vj0cGHqU5ka_9MMTaBE~oqd0*kUoX9-v5F-Pnkn^XXNBtm7@lV3Lsj!wiRHc~&K$L*yhM_*rBVHwzBDF_pFpwAXHqG_eri!9qN1iF9EHdGon30p-iGePm*^raO4HK4%GCIq8xng3HlwY0G#2#!KOJ7HT&#9BKX-Ul7UP5PQCpG-#~&UtXq*JQaylTkAgTg4HdVrDTqtRZDZk7MVk22tm%RUnpZCKtUH#V!Btf3XbaaCb8xbFOf0@k$ODhugi1$xGCMbfEiYTp&P0r!oFjgyxo^IktBR-YCFn-CTZ_moxiJ2GsSBAcqVFF*W1g8x$@xGAM-Yv@SInW8po&ZXB$s7Y0-!RmF8#fchxeF&pcmt4VgYEkNB$@x_Nbr41hxvanqVqA5vT7eIS0cIL#6#gMCqLUdudz*2ht0t~$iVv&#oY^RQ8@ltznYo1M~yq*&_53UXvW#rAR5UM379v2ZZ2wTRnd^U~ymMxYqNLH*cRbon2z#nJf#e!I5kAft2TlD~DUNXdN0*yehyI*y#Lalgeael*J8D8eXPoJkSAdptXsjrSyN74cD$NL-e3VHBqvLtfTGfP97LvB05tqFhsdtC6J7YiB@!t1@rk7&px4Evd0cA4auLY3c^n364izD4Hxj^@z-q9m0i@~IXF5UzpC2kJexU1x&B#4D#*5u@SNjdY63DB6Q79P#6X0_FGell%Tl8H@k1e5s3Plq1V_Y-yJeD-2T5VT&Rd$s!nuMl3fTcX-EXtt_hUIEhG%6do&y4$u3X486jB7UO7gAvV6gU3DUet8rOx3sVAHiMgLT0CnQpRTWfh74Tx@^2!vK5MjFmLEyu#9G6qlMlFksg5TUO3O!Kg#GHwVBKW6%VO$8#M1%r~^iDqxEy&a7Z0iIO&8_Z_JBRs1E#c$u4q7C8kxF%96$~^$Dq*IK0wm79Fb0h&W94IB4~HFK6M5*a1eXSnj%kZo5B_2mJ*dcoZ3yxo^9a$YtkkL2HbbDo2^a3qd7Jrz^Q6g-U3Wz4FAiQy$rI-9rqfU!4o_pu2!Ue#a3BCVIaiBwQWSyJOV7&q!0uz1#gBCEDAsrgC9AcxALp&@GR^W&@hnC@x7bhnaz6*~1XN^0^5Ux1T*75NUTCdY6ZWAJ&0rWH~XCl&Xs%tqj5c0pV0F-!S9YikbDS#B05EnBdXWp%oMsh_$_vXaNlEjq%rhYjjus6Hb9dAJtiU-MYOcjO64VGDSlL9G_T$eoJ4^bV_Ay^AfJ9vbtCupLLToWI45aczY@reukm!ODyO@DysE7OW$0^%jHq@P$nKOw4Mx*aD_mxKQ$CA4K*j1VwgFDmJt9p82@b44_7UeFxR_6y-mKwIn0oRJEfBiB~mXxA_dLEpdw0IqB$Tb4nKV1aErndS$v_mbzY0n~284B8&K$NkfDsrq!3-hbaBDbp^MsERS~zSHkYd2wm_nLqfaenijP6IIezFeE3B5CxuGBt*1rkesHw@!B3JBBhYIL&ic0_OT!gM_ZZxCZ&uCU1G-3Q8LirzLaqZcBQSS6BWH_$2w2b4#wS%24zSfCNKY_nE6RIeFytjHZ3QT-UvRwY3Ndz~txTY1CkE!wYIAtkBUZWFlO7@5Ad6TRHL0Ub*&9GVgCvM-d!e63qNy5nc*lXKexJ3HuVw$nYK-flg2Rzkx8Z~pRIkexcDnXJ@%^zckk7SLZ%7qWs_ejrb!6Katj@Ol00JWWAGHNdN8CAXdBa!dyS@iQ6qD82BRNXt$G4VxJhwaK5lK7prp!yL-L^a1j5*F*_YnCLXKGccV2lo62gB@U@oRpxhTEe86!-ud#VfkBLT_cK3Zqlf*fv@GZ$cBPwe^6Itx#6%m-vX0SY~vZ2#EV-DR7ZOKlWEPKfOG_L2r%b-O-9dlA*Gnmtz8%yN@ncC6J*c-w%vX~u*!iaXBWoKxM45ZbQeHPW--xb4MtgwJ~AZBOlOci-WEpDUOWcD@pJiw12-WUNr_IC0jA#Nh6v%V%Q2pIVn&hefp$@3ea~LJdDOsIrZ^TnfPenFLUq!sw5F@npg43lwtG-Wwb-fwEljdUj8LQaw!comd*0^!fOmZnfXVN-_Og#M1~9kCxjvc40B%c356hysu94PpRS$h~nBxROJBzRbZASIgwjDTwZt-HD4Z!W%bF$9yU9szUr2zhEvrk&kjdxv86X&PZSPv~S9zDSLWeg31STfhl&^dZSn$UCy3MxwCbrzh^j~-nxj$56B_YI#Meb@dVkK^8e2@Vwh3enLi7jH1uJag3HqvX$xf&X@AlqHherz2N98GpsZNyZsuFYU2flO*cF_NOij7#Z8VCjz0nPiQVsUm^&NOJ7TKsvLJ56$xJ5yebM4EMDV#yjw@gq9VeIMiC&fPw1K*Eaq27B7Z@F0Ll1p47AOv4$bdeemuMKyLvfEuwSbb87wf1gkHCXma0OQ0xVQgvxAcGpUejr$ZXply&S*K57jO&ZGeg34M-c5m9VUF0KHMOB22SrmGHJf1~*a&i0!7~psS8dOo&6u$C#dtf7*@IU54RaeUm29!nV-sb5KsOZyKZth5J_0SaY%NEVSuVyIaKIFCvJrcCYBYkwE@$hSiu^zOV5r14efcfMZ-8W3q##@rbJxQA^ka0Cvp&^Z6EzKcHyPbOsVfHsmWw7cv~QW1Fd3Cc28CI#3i7BrG_zCS$He@wjkZQSU7-0Z&M2H8PTbFBFhUC&*uuT9VSSOMu&c*T^6u5ciOinTvkkFs_D4mKiLUduq%xJDvzxF3hB~Y*VFfm%$s^&FQBl5NnKHbUK&bHMoHSw-Z@evE@PCDDOlwPSA2t@v4U9^q8pfOolvVTd7%YC2HH8aAgXu3w35i!^8aGSePakxbyDz%CsP9%ddPNCEyLl6eruQ@tB8_G7L6WV$iC4Q#yV$&&UDE4_NGy_VbZ6bWHFds@zQ-p!kK^xMNK~AhJYXh_kaEFnkX5FTx_gAW5ozBkQj54dhrHGU1huMPKiFbBn%E#gHFE1at7A^QJPZ87lb!H%w6Zb6M&KXoWJFZpld2&MA1fD_jCKfKZXNQrDCs&2qlToCbNj7eGtJMpjTSakNQ&MSDAydzQX!ZgL9_lqY3ywbp$fai4N&nrH$lip&idg^uPiX7v_tXSU_B310DFWs7mdzwhGo15O2fquEPDx_CjxDwXavdWZk2RQV3~h!nsxkbGO0F!3Y@4eDihe7DHmA4h~yI~hzpYXyV@XhunV#fpJQJ@*43gjo#waW78jn@T49%vpXYCMs5~OiTg#^KZ^iKTH4~9~_rQPkh0gx$obj&ozl_ks%7!~R-BzhcFq4LfwzSxBhe8jfb3szahqZ^M6~My-p81YbOz4jd!l4ygV4_^oQ03ARdwFASKA-gHD-Hu_fnI1jypmD6hFCDSKlj6IA2IEe@rAc*M%XAj05Bk$@uf57P$nx*R%4~3Ro1@oFatRKw~2G$aVp3dN~brU@ReNC90v&V^j-uawSg_Jr4-~7i@xwIUx6QZlg!sihFFSBLt!~N-DdbWJ*qQkG3VyqQd5sirYECgVq0i-IPyB5SZQC*6VJwD^VyVrG~Wzfev4opT#ckc!w-GDCOHBwWi6I!T4kK_HW4xr*k*Ea!CQN#&ngyXB7gvmEo7@Qo8Mo0X3LwM5--lgqKgwOMOPkyguocL8krDAv8F1Py%534JTKyrmvE&0ADW*cTzeERsFeGtISdjb_uN&M#N#zT28Pjn1OuoHyuy^zsmb1_S$V9mNFROhE2$GCSZC77GcbEQMt3DGEWtC!cPB9~@PDVR#&~2rrd8fYwoZm6iCAjmfJ0mvuB~OQdr5okiI7nx53f7AdzfpFnILN*1zfyC_Oqsgl3s##e0lWjxAy&JpEC$IzMcnlEI5rarQQLavw6di2XG#137t%Fm-sqi2Z_cL1H7oK02aGjDkv*cuVDXp7qgYeFWlvtKGrx0Tk*2!3T3m1T_fS8$h9O0ttTAfbDfSVKR1EHeP0ndRuj7LW#q^dHbrzUWl%PSSYeC3Nxuj#Z6LECQrVeD3&Nh*VSryQN28s_S98rIHaZ!SPaWu8x8@I6Py0Xa2UlIn-_mVuW^Pa8JtRIg4je5FeDBi*$ShetI5XtBXl7u9w@J5qPsJeVHGX8Y-^dzc1xWl-@gljIa^7DvyG%osV6_RZfRH@oUz#aatEXf39Co_~Xy8v#&-wx8wO~Vd%6s*v^LCf&M-VE^UZ4jcOYrfg30b7gs#t&K&Uy8Ex7c8a5lqdPUeq7%4ekhvWQVEvqX!7ST02#Ns%Yg#gySMb0GrQgEGnZT@MP06#Lvf5X7tzWx@c!pwDaMlWyKZrW$PLSe90RiwG5hrAwA1aNeUx6l*4p49PEDMon%rTxbSg&O3P@EQqea&1!pFhy4h$$#!R*J9bEJGQ&5JVxLag84SJ9MNHzXWHP2@ASmKdBWY%LiWsN3Tgnck-d4EZsc~pqoM*y&&m$@#SB$@5mY~Q3TZ7%lWsCW6Kz5T@Rv!$se5NMUEr9gmtjyt7spW9za_BHw24#8ZT%YaheKdOsZh~3AjlJ2P9^Go8LKFED^_LIm$lf2*mmgLYx_T0JoSHmfOH-k&x&!8Aw!CEa@30&*iDqdl^qHy-lXF*wiR-_0$1xeHFsr&c_6S6O0%&6hD9O!U^X-~kk8NUpMoC-Zv-G7QGk@9t23Nkyf9BMy$3mG1qV6YobKDEDmKK#9cAerQnA*6sPHztUy#WVYyXE2UW6xM5UUGp*ZdbiKFBmI25K2VNJQ&ZCXQ^Nx-MQ!NHJJw2pCj!erVjGPZ-7djmFDPL!tD~y5CiJ$Hj63FPOnd51XNof%DsS#UB!eGY2&M&Ny12E~Uqmny8rvMnu$*faG&YJtG8zFI!cRnJy1_Py^vX1OMT*cxg9MvFLLdJj*4pF%k~XCS8P1ZBfiQaEiuAtrROBSYY@6h4c%hIoJJKiC4Yy@j9HwXtOzLAp8cZon3PZMEp8fiXXr1iH@NAQsvmnaK8&!QeC%Rhn6yXcW@K01ZMCTriRn_%nRDWwjMsopnkmJZ5fSB8opO#iY&@OQzv%05KA9yrIQZzRX@fGrcb9hRexC93IrLI^ZZgHIfTY7z%e8Nmzvy2XSMWSQ-0FCCWZ!-N_7^z0qe4ARV#YiiSESeaT6YQYPZIW&mg1ShPP$2qCc^TxgW1d2m0Qf8^Ttd~zja!Oo$mHAb7P38@ZW68u7g^@-Z0su-e5er8U%VqsMhq389WEk5f1xE21U1JhZWj2J%AWK5XZYKI5ME~D2*X2!#8N@aYkwa@1qcYTk-pSYwgzCO2RanWBV1LN#cO$mHv@PCPjmTrJ!5NDe35*_38Y7ts%sJ9vdZfSdVxHljT_OPOzNDzMYc%fO$Q-7#67n&6mFG9np87b&g3ET3XM2Uz$2KN9eVNO9w^42hW$nw~JINHxwHAC9%SyFfLIwZfvuSHSSPYQfu#ttJyHrzu%XmnOXFIUY3v90OsEHZ9KB!Kv&vKE~gc@GD3M2Y9ToFguiMQ!I*Wt!pAjwZL*~TrcAGtrTjW1!&zti7vmSQJxSDgKj3q3qM5#FVgwL&HeCp#E~pwR4zXx!h6EFFDndarrEiKwOcAQ^gl2MofsrF!G0NTOrTY*%y^8p2j_nQzMdllPfFna&QYTqVSTM1xsa_PpdYJb_aebkquwHK9pY@Ea6iqQ%Cqg&Z638ScBg8Xh$$2LsvwGJ10wAu5DCFWA@Y6PfbF3R3V69gy2IPz1c%IlX38dwZ7A5X%mp!-iv^7M5l^~b!-u$#!7WdXVyFG*Y-f7WVISeE9OYCTca@OU8wn^H6a9t1IEO9~-swXh-idqVCXS@A2OPEuwRijYVSOmZUrv!#X~ZF4y3hRMpBDjsPH2Rt&hRcZ7!a2ms_BeUVwAL7WSBrz1Zsndt4gfxI7hHs#LhJV#Z_UG7^@jAk^DR3khbM^-OJ1WUhIRNDJJaf^9j-JQnmVv06TEIJjuF9EZX6~SS76Eh@uIefDfhKgs&6RF#GWX5O$Sc9io&raB@nYzHAGsbx7yelSL$B7mM0Pus@eh9~ap&8X$beB_NW8fKT6FEy*rpblB7Vr~P6Lo*vypHCuwtjUjob4#FTi#iYye4xohoJD*#o$tKaGwSALy3kfO3GmSB97&Z^~ttE#LKKhMp0~!Q&*qCIKl8KoNc_G&ksBE3fq^~%ea5xMJfgw!ZGt23kCoL5TrePWMZDPSJRnRqBeYSA!CurV2xv7qxn~3b-g4@Zp37X1Hgg8BQRqnvKM&vBe_%S1PdlS_7l8i&Gf%W_AAfW-*BTohFUN8uYktG#wc4B!q02aIUQLqte~LW6$KUGv6a6zbkuxz9Rw1yY~KCmQh5%V32g$6%#^TFZSNK@uKeL6#T2~sRAIPF_Xkx9VkP*t!a1Eza&fIZYhPhS~JdqI3x_dKb!IE^0podpO!jgM-@70z$Y$d3joBsUxn4PjRS!bxB&sqQKb5qkmu3M12Hr7x*0IMd9MjATIM5yiCZxH3ZPenNPFq0L4yyRSnZ3-aYfB7@jn0TI3jcwjp9ysw3h^VP!71ulYQ^Ek-QwPx0WD_F7J#TXN@vxzLDJxZM3*L&AdSAczPaFI-#$@34db^EqKUqCEXCNX1kA4gxubLtC@M$#yzb%jtbG9xg!h@HSE0my0jN$BInejUeP%zJjUK%9L@fu^Re_Eob2~cy&x7h&%qIGB#3*4RrM4Fk_*BiN!Or@_z5@isMry@Ub^u7T-w~2TZOo$-1bmdpEll8*aAb_TP5Pc!pcVrEsnFtuH$&rcs-I%L1pCBQ7HPL_Xx4fU*xstckW~vm^hrR&&cgyCflgezRT00^yU5ajkifVpDLHdacUns5LhJqR9z~GqoH7YBxi_tHC2x_u#KGdy#0$1pU@aN7a7rq6VzBWKTQ3XvrU6_4d0^@NsKKs3M1enb&&9wWtlpEAyA3wUkHuQ5s4u#lO3@_!TAfCwr3&CSYkJ-jN-33DQf~&vg9vz&LmW^8gjQw8FE5Gd5T6-~73^H@lm^mJ4FNwSvSyJT#ADOEnCz#Mn0WTt%W$Ft1Z5p$wv#6sa3uf-AQ58hxDT1yqJ5HYoUk6zYu%W36t*AZD6p4DIXB#mIaF^LrNyON4r@8_P~5gsTMyn2bfxgbk4_1iB3WDD!plL-46zhkVMJBHH19UiD_dLou&OxPF~JpirM8rwRhzGM*N2s3jLKQ4~fWdNIXZc#mSb!Y8g3DXu&HQcjQEHaLK#4~EQc#6^9J!dzz8n7QOqtdG6iS8IcNZo*-xrISYD~REpu*qNJx3JM_a^J_dB~82M@7DagsgheF9oxU%pgpPpz~et&$5r5CCR8ievJxdHRz@9_K06jYA~0*FhfAUerqiyqBTSsOgKMvgMGEMmwE9mW_-Z4&LXGsTZQz4fapQ8HSgz9!Hw#6vwY_O_%PUjkR8-^Lk$hYzEsjhggttl$pto_iqkV68DbNVeha!^lBXdAccea!z~peL!AJgHyALj7saK%pZ1N_dF4szZoOx5y@230kf8MCsN$D#zI$~K-oqBUF94RwPIP5~I280GoO%@*0OievTROWVgC@vr$WCbOT5Zen426&6YdoW6-#Dmp@SUM*iD8xllAQws^$1vz~o_LQqH$-t%9in2gTwtb0RlCU$^QURe@~^LI9ssfvf3tR2AdJHE3LeR%#DCW1UV5Rl40uup1I-vB5CroHcEk0&m6CbJls*w@OUhoRC5MAj~_umPAq8yt1ZnQ8xofTV^~tlx3Q8%^&5S7MEu@%lM2%WqWyXpZ&HZ9K$N31zPma-7fd#wz-pL&hYf$dDSN%cZpFci%2VbWk@Q1lxQSiDvL6UlUaW0TZC1o*F7sr-kUHLr2vr_yLvb6vd5BLRfv4$vEED~6taOBRugQv1$L$g6Gow4-dNAw*i98@sgPdyWOPB*JbRE--L2^CSPYrQKRb7Q~Cm%xTS@1RJm0&F%&jzaenjGB5sx!_7#*zohi~RHYQUvh9-hRNvLIZ%~0&2Gkp2-LZzH%O$#LURAnr!3jbv1oXJ8-DM_DODxrvpFx-_^RK$tjwJ!PRU~K4nbX~H#O~wmCF9PVUomy_N9@ZhyUUaqg7GIM%rFMuF3@auVnK7cO5l%lJ0*HKF0iWUZSM~m^ai0pC#Y~I6WP&VcvjT-ue5yC$lYxR*~AQGnjdDI%Tn&J_H56e!NGaojz6GrtBCYrUl9WeT#PB$kJ!JqXNmx#lBJL9hlBsbmQUNzddRKJhom7pXDiQ^!-BwrN2vVGqH8KT*1SN!MsGbHcXDsWX7TU0OG*f$$p1pZ@anpU&9mECsYo9E3!OJ%&QmlMLpYNXTgXf!Av9kex*C1Qof1g8OHdKvU@73OMHl2_-u3K*WJxm3TEcu#NB$f^D*gdirEUZ5Za!bxeC7qDN29G8Z6GaP30q35WKQ&3h^2*ulPOrqGr_ApfYlR5v2dd^%Hxms~OO4vXggki9Ql47XysILl%#!d40mtdea4mU!Y5&Q$*^8IeqqgFTM~f2GwiZWw3U$ODvXVQLH2-QcYJ&SK^Eiq*kPdiuFdZJk6#xF8dmLQ#0wJ2OSf@XpVBhXg#00h08Bkm&xtq_eSgtUVOt9#vO$fVDx9*%wIUfq*Y1sSDrSblececg@#TIp3$ju9UroxfKep*jn0SbJEGRc^c&pFRVnsh-57qCysAvUGQBR_!WObA%%XA#^bNSF^~I*D^&brM1J-Ha_#&ae2$x7^9Zr2swdVxYvy&eU##i2n#Z~PbiGBve&#aXX@sxIUd9hMmyqGw$WG8dv-JEfNyfFT#tSEBd4fQysyLz8kH9tDrxnz#8NpkyJ*4bj6fL-u@ihGEw$k%jr2etbXS9c~bKLf4k^gY5g~Ba@_nh_ORhqrACc%9VEq7D!hu4jCn0dQ*iCIJAzdzrwaQbzD95nMX!vbzdDGMxpypxVHXa1goMvo!IKqsgC@LbNTKzENcaeJ*wd4%2CcJPmde$QOCxN-nS-tXlIEJNxS3yjSxHDSC7Q4*HBbksSBnFhGs^SZd%VA2#UTdInW#RI40E@sKaK~A50AvqBD%Qvkhv7WiX1~9A6Vb@lMAcXo_W*I8CRWVV5-_PjcQB3UssLy5WCZESfLE4NNx9$mkuWP4D#M2QU7i*35CsfcC94n9Sr!^W&q69T%xH5hPJ6rsZZnTfFwK#POxHa~^hA-mv2O1apXP2GpY^UosGYz$I3CoXbRh@dQ8bIVpov!*Hh6i9t~ueIGRE0DTQ&sT25EoprAh3f7Z%O^vzQv5uwf&0nQH@E8aJ8UtD9wbYtO2&r2Ni65!o4Z*Dt*4$jzNkRYnDT*EVD_KPVkZ$b2$6h5Oa@b-oXJjvO*P~_rKkKdugHXBd0&#HBifF!#zJnQy$jhn$bT5kF#lnr~2#O*34SrNHXw8W8wX0YG7H0sAH#IJL6kh~3lHkYoIHEZNKsxrw@7^F~ETF^G03tOecluvK*0P0NVJCq~_bL4~%O9-XiP#B^1NKSx07n2nMy3js-4O6Ef@Xz$m5Wz~PE@_p08^n2wGOv0x9!lYogO_jUu&&!R$-OtE61J^%tuOQl3SiIq~sVWluuHFxNM*9H&55knte7ox8&ywja3~uISuwMmCz^PDwOtb%CKzyAbM^hcTq7H8X6m~tB%i8q7O9cZvXR%xjf&%o*@~u^OJa*3SE1NG^wpe37WKnMSDAV_GFHfLn4If^^dA~r1&4ux2EIEP@uam~4M@CNdH^l5G#bjYzvvGixmZyVnl3M9gYTg9mYVIU53ZfqdBQqg&Ey!sPUYAcgV*oruo&rFvM2&Xo7LLDuqu_hhXd92FyiHXj~kbWaX7Z$8ecqvvaXIcYXi#DFbIqSjtK~35uXDXi34N0zE*mL$k_ybSi4KDRhI6xRLl!x5*nec8oDmy4IQXoB2SeRQn$h@h19AJM#Kl!DIj$z!xa^RMu^$d6iCa~WFlCBi*49xG4v8g2oszUQwz!5XoTGrJVjUXF$OejVOfIvlYzC@lvbvFMQjoy^8dfCjZ&fzRyHo1wfghLLWlN7#zi7mb^JFOUl&8ITjDARuqWJjiwljgUDsFE_HiW1^Vnqf%pp_Ty5T-GuQBgn3krQ7&m-p~HtI9v36@N-x%_XnVBYE^al&6&EowqlCV0!RKHKE$xi8%pWZ#Z@Sjkb82m@wEntKGGv6o^Md_-V61G1pmBmi-g_l8odUiiW^gE^Jjh7-xYJVW^fn1~Juzp@4fKn6YlgyGDnjS@lzUgzjQkqrApg*f72brui1_22N3W!jT2X#chIm5GF5LU!FRgX9HvulgMZY-AN5@oF%hykRkTGkjKBG*Jg7FfpicJBu@GGi7wCc4D@nb1Zf~i%!8Fe~EF$U3lLu-~B^dGj~vCoP1D!aUoHBIo_n6%OF@DTl-c~yRsmz@oXuO~tI_g$@WYgobop3xjtU2*L0v%cNEfzlgTiN&uOE0Iv&Xm_QWe2GmM3egp!G@_nlx-DXe8D&chl9m_Ix&Cby0eIKxO4CcKx~PU7CMqqpbuSwPZc-NTjVrPoWsXJcB~~%c%&y1No^fyRC$N3sR-5cwqiw_9FDi&WbP31Hup86sqG^GA5jOph$330fwC4vsVu7FEp5t~#RdcB-!w2~IT6QbqOh5Iqbt9iCOTT^c83~wTOVzakES!_%@5~^GF8P%S$Cf*LB7-$S-3cO%9j4^5%~YY8@R4Tv&WV0^Go*SK2~eI_k4bVOMFmYJ0Ql$DrV~X*MXU4qONCJ#f-gC9%!lP7X3Q-!ZdHI$%@slvb6H#VUo4xLXRiHgUPGQfxM919RU_LNSIpqbpwi^wib!vj-%s0%xq*ymeAAQtu89$en8uF!SbS5CmpHwajo5kCX!B9P3fKPJj#@kK%cNFm5O_2lL%uE81#Hb1ylY^gSfv8#t7*2JUi^*@VsiwcnwQ$#TtnyvQ$9n37~u$jNSf!ry0aO-P~1csazh-yM1iUTKUyyFEjksALLM0HbJS%V3g_NXs8*DmE3CL~rHb~CTwD~r@IE^-*vbHSdVuygAmGD-X3FDPhK35LITb&lzYGcvTz8PA5Wfy9Cn3xLFAP2_Zy^hoMF^h^xu!o6@HkmrPCLq^m&^Z!c*Ir1d_0%aYNkXk2y$_CyP1hFnA%yWVCJlzZbh*aO0mAfpYucDxZH^gXYTd5G_HEhKo7bA&#2C7QXT@~V~exni_m-adm3i^RM0jVq20ci8e^zE40mx#XBQ@P^v_5JsM660K08k#aXrHWlCtPKZ8bIoOQcWrCtse&1vPqsU-JpRFT#6fpnxZsFtT4-GJAKGI~2UUAAuPNPzMe6OqQlNWE9dWZ1kJHKXDe-CvcDV2k!yGNmaXto-MBl_Zl8uAjx&zCPumG21_9pZo5GB4#$nB54Bdo9VT15-pR*L1qBI*k6cu%YPi16Od0qdLXyg#rUyBTh~YtWo48dRwFpI#AvxXkybKJvjtxe5~TJ25^U@PFr$dZ%tX1VmA_slChDa&TE*fhTXqFlSSfv^lBqWB%oze58CIv&mP#3Xeh&pSj2Wjo^n-%#AUOQk#6*-Opjr4FkWQ@6Yb!nFZiXqKw_o&anznJICHJUApUl-rhqnEpARFL6GSi6qIr1Y~^%&AWbD6J9yj%BS&fxG6y1QB8a&nydTTieDIt5YiGnbLTRebbNvWT!s4Ze8xs#o!Mm1ML3ThTR4IoRBGT%52gDs8foVI7NcOb81Qsd%7~W@M1bXM^uTrUT!u0xnoEGlvQeVJi^LOeF^jMCZpdFXtlfvlP2ZMs~9sUm9dskUUHuhXzJcjp~$y#Z7IFJBVV#p0$D$$yt6FFWNvEDXFqu@^64@BimUvVm3zu2Z^Icu*fqpV^6Ai3h*9mgjKR6yfWUo*1En60&pBz#tfODHm@$qCuk1Ys7HMqGxo&k#G@R-GC2W@!!O_b2bs4pw51Lsp005UMMetfY#b$zJkVN!lKLMiMg_-J$ZyBg_gp4W%H6T$Q#NEFpp6rRKftGyZorAp6*0v5R29Y34bVjeH1%f71b5JIUmQYY!!iscZNgJ4eKfWq^Br%hB22$@7E3xeVrxiEKEtG@&lFZQWH^yE_$AuCt8xCCcywISx-oDP$~~^TbT00tcPnsxd9szu9QKMz0LrnCRu#lZVnCdNUXZ-FRKyGM~p0b^#l-jWWN54$V-CGnLKMTTpRzsQY0KhnE^p13R_q*88j3BHXnxaGf9%mCDWH5^P2Nzg&pymY9%bq_GBgfPZ_Sgqyf7BkjS*DNAjyzhXAPcBq%*q**$Ozg842mBiP-@cFqPkRvsoINEsvn6E14RsA-^_T5CluoavWB5UCan6DRFvtoW7h1OZzC!T2n^I~Wnyy%jacp-KMk$4pvdEpzrPw4&9oiDTada04&XuPwU9fEo^Jp0GUF9q_%BqaipmLIEdVpSS-p@Z2uapbayPSJN41RGLTOpVG@bqP6r!MyzmJqVFEzf#lj01CE!M_h~gUdhZzd~bqVYuo_*TEw*m$1&T3~7obeHsdFzbWnEZn7efG9^HOqFCX9#*Lv5B_tMn#J%Lz#pxRFXw*uI7d30IPg#ogMEQp4PxFnDCzsMN#gU0gwnv9WGt5!FV8@i90ho0oyAxCBcO9nV81PyROqqe*5CXZ*Q$Lw93lT-oEtBsEkR1e%~NvGlqba%0BSabUyppk92np6r~ouQ#kdlM6CJHEsnEsEn5^Et1P0HbyzX4Z1Gi_1o9$nrxVQ1dC9BuKBqdA$Xd57YGdvn&880sspwcedgyU*NnaZ9Ikh64pnox0@l1eHv&4rI6sabn*vNChv&@&~hDYeN3tHF%_DiyyR48yhOzcGbJeOs6Lv76gi-vCuedo2~54eQ0Q&akl5^CviXYXSc0fk5~-%fP4Qyr%B5TTHU300f&z83DNjG^*VCVR@XFN&s^_NPs-s3k5sW%n$&eCt@hC-^!pM8^RI~!U~ni6NOkS-8B9TaK5EIJYoKj3Gl82zr^tRp@thj5Mw-D!w7yo^Uh^9Y4j4Fm2sqymN4FeD!GfFq_t*N^Ey*_e%ZH^-yI&B1ey4Yy3YL3!loXbETGO2QxP5yr$jZtBuR~S9e20L#q1I5-m@U~MDvDJRFu&~ZZUsL2~JzfPDdM3oEq~ErYBf$wDQ17n~VXBAwgW&hAuq0mEsedW8TR_&2$sjaxJiWy$iawp8hXSfkFyWbHjGq4C0RtV3q~WnTp$Zq8aGn6bl#plE6y^_QWmFjinTih^vx*!itGilil9lRT@n7JwYfvyoHy6jA0TM7vg%WaD8npm0THwbchrmtyXYb_cHV$uUYZfhquSOeo_o1y%e_ZmJxNl##BVuaw*ju9pXtQfVE!U&HN@FRhep!flh%jXZqScXy7Xpwxd51rHSralWLhZJ6TE-iUbh1D$W1fqlohde~M#Io!_H-~PcXJF3KBdkdGBMPTik~B@@M&@ErINJ_8Bd~a*Ut#-x!8iwUwvUhCLjHz&s1!fL@kZoXyf$oVGXmVb-iGE1zx7CcrF2GPskR2^KG7Yq2fkX@3wQ_lU%vA4Jxmc4b2g2doj7i~Iu2ky1z5sB7mvlxT^eA8Njyfe8fX$WB4OkI#P^XYM3A!1#n5*j#vQm#4uGS7Hq!FDoOujz%MUhdqqgwn-Yip7pS&fz7D!kutu2l8!!bzs$-R~p3z$77GVwKJWIMtr^pOTE*in@FRFPaxXMcL4na#5ISD5n_0YZ5*zjlaXgk*#DhsM1D5UJz7YePds38fNXHCz!_h@6No_^NwPwKSWwlhL_ITYZhUWsXQtcxybj&A2q2f2-Em#f5ty_Aqh0vHjxk0AoGYDd3%q&1O6~H3$2yYviMdpKzrckLGV$e6j2I$L_$yz@PEm#3pJb78q!T$ZG0cip6Q^IXdvbOcNNXlmmK^EZL5oD8BJXS~^SmUJ$fLF0%Mv279*k3HqMp&58DO-gVNcTWMm^ddV@pKUYhpS7dirvQs&$71r~nYab7zJfgR@D8xiD0GmjwFpS$4I~qn!BeK^qzEIc%1ELc#L&2cBJUaUcC0^^nwZGd3f2~mg~*$Gw26WQj7GO6~!QSvsQYRxir!QRRrnsiFmj9WlbNA%HwYCv0@wPzHs$bCV-6B%byA#Ek-HlRS~7X$e%nDINsfQuU@kaPIm6gj5HQpPdB*#dQgTMGjLYRq#Z*bYB@mue#hG%grKkx#AA^JS!hF$ZhWCXqkGq&*oWnNXco!252#re&vtyW-#spXoM@kuqVyL6RGAiuuLAs_vObuf0ELgIksS#a$D*vm0@FKJz0KB^xGvcpvJ5pGTAZ0fzpvPB_V1QH@@sXXVMK$vHF~R@0wdY#UpquZYnjX95u_tCP3C^73#y*iYgD$&Vl5942@3u7gD5v$NPuMmPB0nfG_y2Gd6!i^2hVlFD1*#ebi6CJ6ABUyEP_bOxNrfq~&Bpp_*Vp@#WIZUoTs!a!A4iH8hbb7hrrOA&a1aoxEQNH~KqP6!35kq7kn&PH@XmZnlu@nyo_5yUu~TtE8oQ8ejlGsNaRojL_lm$0h^EXtOvU7axr*qGcSfvdoLhrEjIbE4D0iF2GMIFgvcxBc-f7pioD~Dj%fh7llcsk68Etlpp$^*u9ImL8a#TySNhejWqB$NSrEi27&TAN^Z3eJHc17iwp5!MCkZegrB#rLHV2ljwcXrZywMEk22oRIc9DZQaW_jU#RdRa4FrbmvP#k5OS&i%xWB_rv~BQK$t7^$*GFC@^8u@9L#!6kQC&O4b_OH8Ok8VD6-u~m3wijdqrbNoPPqqe^DbDOnHt1B@9YXBgf@is4DHjBmpnH%*JT7q5_Ncw$QEg9OBOkLPfVNO@sFX@!doPPptMQQ~~~Cjo^fJ5vUwuaMNDKY@ZeIegRc$_L#gcotR*E9J*jon7VbF#$2xAtXaVSZSY6in*DchhpKb&62SD#eRG&MPaExJcI&s%tn8AN5dDtRh5q!yLM&shwPcsBrhYBTboLbFh43*OFLbsbKfWCExUrOcku0yo7cm%9&IgkqK9o&UnVu#Pq*SZV4mOYmowt-K_$c57G!@dfRHd0sYusBU%X&lKPJ-A-IZgWNatkBZsQ0Ia04G#WOJC1~vAb5$k~U8v^^QP!F$lIC*@PtOeWs-Nx6e*ZrjK7JTr4kQ5D5jh$5GY!IKgxWUcVGHq^%v7jnOJ$l~3m7o$yl#tuY^G-#hhjN@75SdeRGoDjfGPQRJILreyD-3L9Dshyo*9MM1x3aZOCXHDUKfs0Dd@SS#-$vdLDXZD!iqybQYl_hF1aKBWNAL@5BvOf98mj*cidUgXaiNB9g8Hr&s4D_o-zH9bzm--WhloND$BPullqEU!irxmvF@Ik_5jsq^&yuNO%@*N1lwL7~^DDL*j&tRltVr~C8e~mCyb2%Ymh_hoUYyBO!St5z**TXpf~9C~Wf9UMFtvavyag5_8AlVt#&%nlYrciYh&X&E!xU~K027xDQE_-P!c60FHEgW@WB*Rti!5xtB#nj-B7%3%THlTrGOFCt_#n1836vuRkea$ZZzS$xDe~4Wlcb_BvH8kcmJSJ-3WukYaoTM^@$T@kq*$!j5OfyvXr~m^12#dZ^Toj$Dne%uiKA2%S4S@BN9*h0gQgE22FNmNQaPx~bO8#0-%d%i5BE@C5~DlWsabsTkYI9u6yhHE6uBO01Wz#0#SFHl8rkVdrzX_6NFF&B3-gC*EUQkmzHs_kork%#Ag~SxtLSk*3a8pNznJHkEr^Y!n_sD@Xm_v~2_oS15O36N8!V0KeHq3L_o4L72yzR4z&hp2eaL-&Z1CMTaEkQ#_3IBWM^7uouFH&E2Qf9sDFYxSrcDs*V6M#gV%47r@@BZnTnB!m6!f9FvJbCxl8Y$FpN7SutQH5jOXXz@elt8R%vkDVKT%wusG8vtlYzp5gWpB4dEja5tN9kgCtOaUJ!62Zy&_SK^hIL-MgxE6lyYOv%U#7lxO9eWLKriwV1%x*CekVS%DzM57E3~wg-~zEVeVj-2T*Z#P8*Rg&uI4Ovg3nHW~HEfV^#gKek7qBk_0$jqIPw07#~rUMjI#UmmV6-xXD6WMv~CQ%D2CJA&qp%XhrvoVfjyAfFW$u^rf7z_JbJNh7l_Bf&kX_7Q9tix^hcYC%5c_Hvv5eXo2YbyA3-BbCb0oQ~jr&nDsGz-Ll00~7G8vC3&3ac7pjcaLYT%1n%xFyUGGsLSCa65PRTZH^43XTsYuk@&-s2!kL8DCjBkj1b83fL&g&$E5UPtGfVi3PxDj&bdAc2#oYkKlqQrqDtC$YiCkf2Em#7O^oFNxT1v_wmds$NJnWSkBpw$#FCsGb#bG$^bDIrF@k5IOtc^hCy*ClX-NVd7TdM~d-UD*GXBtzmPJG#0_j^S!^7*FBH$GfFr9_x@%yK3Lbh2zMcEE5ujE38a5A9afGYnma-yqZ^4rbs!!exJ#@&5rpoa8QfgKM9WTihGBbGThf8i7&cIilZFjX6t%hI3%qQFtzimj*jotp^n#a7MoD!fLhC-QpsSy0r!y^0V#~&#Q-vldA3@ITbpclkfidglqhALA2pwVbo3zjI~Yo2bVeBd@fE*KB&ssbW#@YL%0L_BXXj!s4C4Z2kuKJ#9F~!un#^1Qz%NALsVKsffv9ni2UrIPT*RtbiOBZk5V#PCg*I-~2s#@kLnvvUZUgGeDwo#n%h7xqr-XN@7lbS-BHRmo8%SYU%k%T7kPh%pJSP%uWR0SIVanri^5sxK9bm1-3#oKgUYMm*nhu#-NCyRR96IX_D^lD*iEXD~lreCJ-ow6W5%-n3Yos92y0psOIlEBk4D1~sYzwOkEVQEBz3LS*D5X~jGBtleg%4FMQ!PVIk_G&hiFirn9-LMS^F9iiyRalt~VVm&%DsR$DCUewRerI2*0EIz75%Gfk@7K4v_mmY4_I4Z2m0mq_*8pt_sWi^IKK#EIE1LObs!*cvf7iQSYfyzChs~*Hx~Oz5Dzf4&%%no5Qn8s*$zgrvb1oGPBW_7fwh-TrE_2VcNj!7B6414ifRB2TLeOi3_q4mMWg77KClsRn2-6CJ*h3~OX7K!mC%hLuRjD8cF0N57x*Wx~C^yoLmhN0ARWyo24HY!3wB2L4w4xDLy@i40~s#@P%VaVq%&2mz03I9cn25uWjDA*xOKN1HSodxv!BAiiRrU1WFImBTjrb@65XHxvBm&jir8h~T^8K2RpvcAQlw7amz8BaOeNUnHR3~RV%1SP&OfUq2M8BJclekxxr8Ij5z-qoqYqP8BDLw8~YrW~h~^*u6ih6LnV9WcTf9FVw-UHP$tC%IV!D4mYoS~rdl-q6jA#drEj^#MqYLHIv%N%z1Z3HM9gSeX_4zd3yE9&CK9tGOi@mZGJ2isS5_NLWzia0zr@F553@dQR2HDwJ6Cep$!4^Kq&i!GOLY9-VMQJmT0l@&ER~13V3jbqkl9q%Kk%*fmdYkRiakz!dWGWJKR$fTVWqthufun2QzSGgLuFsai8m5II@icrez$CLja!8cEadzV!s3WL@YZwY8wibMckDuGO@XVo^xUY4UO2hjfEyzMbmb1enZ7WSD$&D98*9KBi-_q1#x3kKc0r%ip_nHj&hAhSz!%Y640EoUrGZozJd@zKIKX65Kmu~S%zNSijZ_33nHJ~R%s9v2e6GfPcis#!@Azs~wgDW4jkf#hVX8-!JA_lbuFmB7Cj!O0om^2Ghz6kukezeddH~fdFbxSf0%R5O#WXQ2a_eeXkkkBZkz~OBD94Q!6zNu2nG_wrZAxh@O0MGXqfK%CBu$JpvnWg%u_WiAf04^$j!o@~ZzvvTDc~u5Mxdg7dQvwPGEZ&Sb8uRY6_X@kIADnKQXJA1x-*qh_!hrrc-SpjNH0jADF&k*&m~G97rI9gU^w#k0EiHXWrfZ%RKtg$SM4@73dgt7$#DH#8V%!O7^!kGVYFUvyAS*hc~Nn%X@eV0QfNeU4KY9pBs2jpFUsetHXh5WbEBW2@zP0k*~!*OEWg6~-ylEKZJ1s#Py@_OQdCEvEFsA2E#DCfgCM1DvLmUbMSHh*eXSqL8!azu!7-hG2Z!T_rHB3u!bN*qj~Wzp3O3iOSfY_KldoN_3d^LZR%O!j$QzxTvBLXK!yvhNGa*WFomF7jJv0t*WLnMOhGB^YDXyv-1ZUQ^Ev%-d3oLBtp#A0Cw0Fv%n^uF$LTW#So9lIiTeCR&tXMhTcK7o3^xdCjzVI1crIN3wJDj@W7rs*Sb^qwoa3&vSVAy48%inIGFqhhG_ZjL*ZN7IDb*GjxmBrPqA&Y8NUO0YxBd_o$HarTX~BVBP58kTqP1KPn8Ls3Mjmt~gnLcy4Z@gjxOaS&90^swVn!-Y5S5~_~Yk5g8veecbmd5C5YJ*~*xOD1#@qdTyx37INqHtW&%VL5eMIqBj59%YFRq-pmvDZeyQP7yHNLEihTyJ%WjFuUfsrMJMwgm~9$Q5fwO_f%#ekX72YWNHVFeWzO7Vfi0R9O&MZq^Kwi0$k*%QiL5U2ym~9SsU@GgPEzGcg&h__DhCR52_VxI%Yog_XBm~FWa2Tx0Y7mq4m$zRcpKc9^vTA9KFrtxXo*kOwckguq7!et^FAu*Z_RrqbaP$NuiH&ZbZXMxpQxi9LHukwogY-^Z3BKMkmKh%Faen8REYpeIp_nlj@zP@SdWN-EmBX%4yhPMXxM3_glqqn0!WEwOLOVXz7t^aZXmzrZ##hQ~rB~pam6c*oxnDZgbRF7Ik1Fs$mM^1r6wg-H@HIEaWim6bkzDEaKm*lvzn@iMc3Q%U3pYF#Ge8m0p#XpYcCa&Ph$aBOT!B@Hjdk0!d*7HQ9DebXGFY#2gGomp21!Gpn&G21MN0v#FBrcHNtbkEp6Y8k-l605c^pctE%^QN4pb8nkFRMZueIh5iDunYJPMoeg8yQv-%~h!ezdUi%nHpn!APvu3CH_tHCGPlCDL~CB&MUiDQy2@^4WN1NdwBVwCd%m^Ze6rM9X%@p$U6XcBtq990pefg@UD8YRHt76H&mb&R8^If9Y#O4q2!UOX~B5Mn1iM9#^s*sIVUzKLTpDSpu4bcx2Lp1d6Qsj5wkhiZhU_ycI~7PkNYwnPmWl5uYDAWhO#EkTzuWkthV7G1_Xfqq!U!_ilQwmLMZWqaHLrij300q5SaH*s!VNV!UVpseuGTDa5FsamHxoZ9-bXzAOB9%uNwyEaKBdy1gNiXC%ySYopZ-eym^^Ia%9tlkazCsb7$PnOs_le9UQ$juARjMJ$Ue~%KoiUIhf#b~$eMFmnCTukIn#dyisRpcyX6S!V_if5xIvaWRqJJS%5ELKC&U#$loS&R%1hnL2!p_ONXK!D8%OV0o!v3r_bx1wOMqZ&Sj~CW-P#96DqX~g56C!7EzVz20hrX*2_!!lshfKFdatrCEjgzHGeA9u29HI5VsVdTHC*IW*tIPDss~eM1^bRw%7brgMF_#YuEg76dL7z$qABWVl%Y*U%AK@Wi~Nb%hCNA#qHR@kd1jLHJ^xV*C1U$cMyFL-ct7_07j6gEDEV7!^lzAC857*3d~%2XqnPYcSki8*^U@NJng6fMVw5!syHc31jTN7mjiZ^SJy6B39r0N54xx8O-Z*m$b~KA3LQ4FV5N747awXl$DaKN&ChKo8M4#RdrsE3yJsP~0o2Q!g$8*I%#bWCpdw6fFR^pEY76EscYeDO&$Gq-&OL0LrfX$ThAdJO2V3&rK6F!wr37B9@tTCGvhwdCQp9I@NB3EUMVk6dk72MiGY2PA7FX$Oz_PMVUUe&W&8~qZu$BV*Dze!WMvw3Hv!%^G1Eq$PXGtX&%KW2kbXU5qnUFw#-hQrCVX_HnhaN@A%1Jq-UjQEsIJv-v_xW666vxl%1^b#67Jf-23v8&mx%1lKXy98U1MPtz9tdgHGZ*R!wVPYCadw2apU#7NjS1MbA@DHN54FOv_e1n#ce@5Ef_uEQrALJogSV&9sgTz5v^PBZ&Bfci0s$IT~T^ZI$#V1Ncz2hZM%tc3zkltk1EH@PLXd$~_q69Bah%FqLAj~Giu%PO$A35LAq7bOxlN8%6pboOaD#WX$8Nq2Kdl%^LyJSdDQzZfssFDiJ!_@no7lVs2hvplQIa51UqMzzydCaWD%5Wb8%KBtKq8XPsL&&uLcz#4jr9#6YJFS!iOO@&y&UatuaTKG*M^B!mEvd*Ee&WANARd7%G03pJnXEkv&uh6smX&**@GJmp!o^Cfrbx_R1C~XKD4_%a2n49b~cx8kF3hET@RGTApDhN1j~Rrk#TyuOs7gZMPT54%#jHRvHz6$EuRxu1PPd8%nWg8985kfNtDphSWqW~4fzL5m$U2Obeofj%!Uefx_bM3iTC7mQ$&OEP@PF_ADqPS-ivO%OdKeL0q8jqm2LZvMhZPs4YxYmc#Jq~hr81C92iMd*Hs835*MU8*B3Ptqf%-hQFJ&Cjkfm_$WJFvsP$M0A!ffUiA6Kwnt$H&lbGMcj@AzH$CuP~qsgLgtGf9fy2-&ikY5s@ewXu0hc*T#O0%AiRJ!%hdagdg2Fz8UTszGFMkO12^i^HGhYHCiLTlhbeo$jRNz7lg!U1Awd_3~s-&YiVwb5IKYm97RXm4&Dm!C-I9rywX5$cOzR69%nNbK1a0d0_7g9@4N23k!W-4$U_fsA*h_eqmFl@$jqFVo!wyYYHB7T0Y1u9748cL&7Q-uf^fR*$HvZmFM^7W9qWU-ct&bF%AFL!yFb2t1jIFDlz#1ys~^-ITkn-yscP3frBu&U*EVkvZMZTff*jtmQMq3#nh-IHN3WCp7#4do2gI$A#vp9LwWX6O2U0TaULMjeq3pUn6m-R%muh@FG#WB3Wx-6Bir81ibyeFT2OnVkUuVX#8@ZiXMsevD^Uv^Zb4-FEDyajlG@FLVtP85mxJaUsQx&pUhK*@nMTq0%^4TUgbRo^GJpx8NTp@iDDNcgAwXcCX1o~Mm3RA*&Qs*jFH4_-vKNK1Uho*t-!znOeP2~MbGtI9dw#c@~VGGS0f_pE_w$ZeSs87k@vpZqo~c@gbUQVfbkl*^2xrgD#73~FVV1n$S14nFMT9-9*dxV9yeuOSYB@Le-fuOHmcGhPAzn0vhHeqhiUq%0WFIPXrm5#%jZVn1%wj-_DppJ!K_0gRVP2~BDPeDthtRnoXgkk^a#_nydV5$zhyawx7i_o2YSgq__%r@PVZoc-lez8*B9#M1HO3b0&7f3ULIHjoQ49Zy2@@7xS4rvQhWJWRUC3!q_#VGx95RgrMTJJTzMJmBFVJbeHs-M@9hq%B66axO!%cEV~W0-l*ddv_TLjaBGytQUqRLQbP@mrWYRlQ@O%iM_110pLvVD48LRpkI_@0e^^hZZ7%nt*p1zkTayPsg1e3B4CAE8fIk3JXKClETUGnDo#Sjc_9qXp6VwWrdfN5434xM6J&Ez16sLsvS7l2$FbQz4Q#bW7km9qS6Cfl!oW9T4-SRVV*X0MKkso2JK%&oLOBY8SZ_Q^~KZeTK8GVR-SeA5EdBDWF3&FCQh_rFirWaqhB9DkRaTPzCzgijovVwtR4-2l^!~XiEe86PUcHSQf$^2wy7_aNI0NLKH-P5LKfH*w_S0ii&F3yA#CZG^a8I4v^cIZlV8#DAax#Mb5Bs-5Jg7ZxD_&ZbdHR*bh9AilyKVMKVJTTkdaIYRnH&PbEmOe~K~O^&s2kKrQO&LKQzWncfqms6squUr$^5fIjmT9cwKlwGKgYi*vCRY75Y3E4xAc!*OJ-@iyd8SsAgp9W~7^I3&6LhvE7-xw4OlJcH&vEDD88YRKjJrj9IW4dqUIQCcNo_ngPgH%Lf0MW-!U$sidmcfT2PNE5zwtufdMXo*%oB1VYSL9%e4Ym^ZH@eBk5sZCJT*%EB-kI$J2b%j9Ub*OnimB7m1Qy_k3LKF2y4sz-L54Dv#XYF312ft5zYuBXo!!k5Scsne&NXb7bp4@Pv7JuX0gB1c9!yFrrbcySwee$UOM$&fiS@E%GINxoYNX2ujf5xhtyDlsKcW!nHfPW$oWIwro7#wLPhas9S_98FE!NWI&mBdPGOkY^U4^*u^BXTlb%eZJ!6fcUuJYh2EFA1&K~$2VJ*zoB_u9$TKRj9E!~#0e69#Q$2Rm*Qnj3vaRnG58Xe9tDJ@hl1Yi0sR~4xwNB^3_je%PIms6Ob6EWIHVxoAijJdCucan^z9rXn&j5@pBu_dXPmtU*Leoo9cKC$$Rfb#Nl&zYO^#^O6jOBhl5k9dIcp&Xp9jWhBhAg2ZicY4!8-3D-ExaCim5LTfDdT42rJbhh%^Y%S!LizYFKq7uUakIaCwyQCCDBo2NAF%2kUI@&*^9mg~3KAGuz2W_bLQd!b#O^uXtIZaz@cZsgLhdvhqVWlmT387!5rHBs&R~y%v3DZld~1Wo%MRYS^1@L0Xfp24i7QEA5Olzob$12UjIiprQ&db$1951QER9dnfn4BHPP*8xGlWf*Yj%2pvO1Bh#~9e0tep@7Cf$KspB36pq0yPkkxVicqAUBeGMCu*9J%SU*@3qJvfQ#yI63zij^s$7QGapuscUmYm0kHiMtGF0X#HFh3mjy3CiKnSzCA-I~SukP_*&9V*Ef#i9uLTo9aa%za@EeDAu1J$heCaTpE#cl02K#ukv#OmSnyxKZ7%P2nZ-v-zeLCt8js*~%ozsdHkFwvcqSO4g^$HvXpecwKnR$ILS689uI%dR6OCPA2&K@Mf@#2SmCwFB7Cf2QnGAbf22j2mCc1bfJgZKQSn~y^WGDj!z*RUM&l0_a9f@gd#qqQ_1Zvtddr7k1Vcm#DsyidG9*sblMX$um_bhw^eUE~dvK~Y9#IpesYkgWraQvtaB0RSn^et%kq-r7W5UuFX2MO@i~ahEUHg24m3Xdq6_JBrOV!fNbnnGI##blJG2myi*s3GJBG6Fis2%pIKY~ExR^xaickET7wLi&zej-4C*^wOhQ5BGt3kgUp5VNunVYbgLptUP6s^SE%$Z5cA*Pe~NghUlC7RtuO5fYmdr_GkBXLTNTfc!&Eoz3lmiWlCQOUJZnKU9wuyBa~--~eTYYhzIcv8zItjgt~P^ZFVtNR&HxaJ^k$&kDamiSAKcjpQmsA#lG7cS-dQMmD7YBcNDtiZ@Wk3xHvDI9LMpuqxrKbj7#rGzba1BhvFQqhZoQ*kATi-RrW97S94~ipl@xu5wvm~d@11B%~Cdg%6bK4G85@cmTbyeHukVd_roudNd8ee53k~H5Pa*PemGWk@B!E!8AR2oV~W&QTc&VWBGwjaV~@#kUdWM83h&mH6GnE~G^ulw83jq84upE!bg$U*Xf75$UAv8_HPQh!&zh86eSz%z2yevK0ptoX*^^fs@11Z2a3k%KSMK4$L0Ec!nuFFh5Y1WntfHqv109%~s5JpwHaR6Q-Z#!8DdOlrs2tE@hEg~x&eG@D4#f5w7SRnOMrS@ZXmUbsl9iKUCGFXuv019-r$C8G%w^%9-Wi3LP5ro9!CsQK%flvhnCQAKj-QN&I@6e44kJuHE$F$I1zGf%&*S&0eTaKZ7s8D3KSW418y1&i^nyuL*qr9*zxqu1NyOXCieTM1rzNCh1##21tCXXleXppj*UIxK*LVtM_6!!gzvb&wsl$$LyvRjkQxBuLkLDSklDuvyzfx*dTCNGpj9PG3FpIO8J_fO733P-gpaLSzY&%bti6vn_k#DmXlSyd&4kjg6RkCocviGi-Ve7~kQWO4C@*~sn&8fJxI41qgq^SO6o0!TJ-pJwcxHs&_ggV3cXhVoxTWOeOdTe!-x#lDGURjja$MGU&8D^TWLjjm7BCzT3Xj7XYpGGuKvDT^1oJxXg4h5BUwxV&i%sj*8wn-%e1#etoBwzlJyvTH-YjpSSty#$!ZBzDOG16ghIYTovGW9iaTpHWPOV#ua3yQa_UnQ~ZHKXTWU$v0JDLyRVQjpGx7HXAA8vbZDcvG9YK^c-R47&qNoCE6ARlymo*jGzK~mxg609*Om*g9^PHU%9tL9~a9xnSzev0vc9$uLJNndQU_bVuY~Vx@Dk1Ze~AJyeHr#qW$ym54WSWGvOliE5Icz1tCQ1#WVzufukd98Ed4BslGwEVz@Ysn8XQQI9wctC*%#FS~8#kntP~RI#7dwy6r#D0~Zys#1@j&KqdlNE3xdiw#H#A$&rKA~CQIwIcwSuP!I2rQ!&9tEQfo*OdJbZ6E5Jo7ZBs_kF4r1XzK$bsynbB4Hgkm~I@ZG~gbxBkCK4z$&qHC@VLkT_sKqFCompJZNuipemM1#YUfIHTcVmW_s%ASY2vKmux3E^Dbu98RPWd40tySdpOfRh0!G@!enjm%lj8rNcrC02e-zTOFC1P-_0x@_SjeofhL&isDYhiw8M96C2oVNR4J_P#TOSf&$UKV#DAAsDEQirG!-4EApFF~7*Djmab^96a*6L5VkAhFYgtU7_R5cNAXTLb#T3xNa%9GHQc^iQ2CADOnnIf%2-lldseVRi4$hdRPui*%xdcU_jF&~jfcm@KTSFtaMbhHnGe&PS~ex*sk*1NNGGpLRs~8zIXxDdKyL~ZDkow^#T!aGUIOTrd4eT%Q^6LEBix0VXKCgfc2v_ICgtRk6*#p~t$dWbc8tPyJGe$F5yEZ&1t-dVDCz7pakeg5xHqg8jSMrppd9llFROsWLommVj*TeLtpGFa%8_&dJhu21aFyN7ImL#&Cgl#uhBqWBkf_f-Xmu#nP1AXhHB!kUwfLKFNQ1CqySBNckjH%s~5u9@dF2G~f-Z@Xgu~d6AE__k^~a!eegFX-s^#Fc*l!6t3H-ltpWTSjwzZA8i3VP^vxrwVs%yc3&%AR@ezsL#NE!HC&69_71B89$VURc1d^~sYbuLCbz$oejhPPcDPH1KlKibZwVzvnSBCyPpfD8zDlSp~VZ1!B%bOFLy!$zHC_Zt~*nd1nGu8-ft^QOmt5sOKvADiKaa3pTaQPhtrvwEcU~RAtltp66Pd0rQxFs^ii1aopyNpf&9oFW$tHmum4^OPl$bviCywBs$8qpqS5&eryQp7V^OhJu^GhHSmSMhJ^rRKvoR2KjIaZd!#Z7th_9f5^lDokOVc5&rJu111ShXpd9RS4MrUC&fV1_0XGcwbPX4N8Sx9KF4An!3LHBuFit6xn!4caSoRqW_Gkj3NDP@sjyxOfN!BVwRpk1e7xp$A8aH&S!xPH4rnH!#dCzBmsbB~KZD-EQHB4%JfOk_lCHwMXoEa$wWrRnIl@E$B6VlU@AlcRXhx9%W&BT-05N09r2v-yXG54GY&Troc5$ptP938n8VD#oT&Sb%#bE%C@-YxIg*BgR_1n0m&u0c^ElycqjIsjgXRV$A^QmXk~zUnK-epq-TuGfacO$f7$vSe&4M094OqQP^7Hy6Wez_hJRV^znKIfXlofN~k5dw-wve41#ZoiCL1~0cMV$-0B2x9IdbsBv4fglyxfA7uReRVmXSP@pgzZO9LIol7*bUS9Tp$P^!2eRO7jACtB~C0vUylz@tc4f8S*LXP%zEEqyuOgsk^6^9oD@030cRFlOF7zTZcWNh9#!EF1lYTc8*JGyunVRzEbonr-%8StCA9#85K_sz4wYr6WQ$m2esOR%7EgVnWW6~iTHw9nf2s$dUxnEXmGnph7b-Ldqr0Z%U^Z66XXaK8!ko$v52Z~8iixRvJUS$shJ~YdJkw77kd8n0ZfO-dbx1I%Hclt-Rd~hwOkSV!%r@v_Cg0rbcSuM0olCPXMR$MDTqqaITacwOn*wk9l@K73_X^cyqEDP*~&c%4Ar-$^h7W~Tlxcdjs*&x4Zz0!&9E#poH~kMzMZLkADZd5dC70~lfM5KHijXhJMzmXU*%ecg%p9dfdGWoRWAV2dXUEV&WHlXI8aef_T~HS4KLcnQGTCW@egJrL@&60gFJfqSOcG~_h*@cN0rkQR6mUAZfxt6*#$g@emdzAd4DwL$9YgC5Dk0$OQLgu&aW6b@vKMMY3C2eYH~31SFv@EqA6*kxNyK^sCwlC0WvKOU59mRGk4Inc07sEf5Ot#vLb6Om-BjPI_MChqin5D@HOJ&MoQR#g_X^WJasM2%SR3uJcxdhjpyUA*HmiONsv2~gp9kPO$99_VFksKkj*xomFr_BoR-3eJqn3w9um-w^KqAvB4^GcOGP_ulYGS&iTn&5csHJi9vv31sX!C2HrJ^Nkm7a3%H7hjTksf9&eW#914*EK~F7!Y@n0@_qj8U3U1BopX_Fd7lfhKktIqdC&wCuerYzclduR*i6Bt-IwJGYbRo&w0ztks%nVDDeKzb47@fps~e^n6N~gQCk2aWbHi^cr5pCPvfQ_3ywWA~!y*2qIxBsASKC2HCOCd8n4LN&6MakxpMEXYEqtJJ~T5%OQ10YBJROkxY2M7HDLqnaU#JDy&SSzVN3ZGV!WuapuiV!VU664kKfuj8zi52S5-V&y&c_6&nduzETzPYtBNwY1GpNJ!8^Q*@kga7phW^WDIK1yB1t76BWIcOOyF@&VtQevwNgkF3Z2CQZ$JAyVOATk^NjK##ReEP9qH9otacghbse2DERk-xB6#5qOQavl0Iu~z-7ibSxIOZ1iq#ysbBLP~w&0^Hq&ouImoO8iMD6Es~AM@vRC1sjqeMMZAE*ZwE9MvjgSZUDT6xlYYqlRwVf39i~RPtoUw_kqT@xVfJxG9g!U~bXLNA8u13SiVTqv8-VEVdHgSd9zOUIcEsWymO^q$9MFLUU~%Yq%Hj&$JURmu7I@cLbyu2in4xnpD%I31RdYiDjvk9jbYfc7UxendSYmHAcLaKgK&IM4V1J2KsFmOq_lf1G@^Gxz_IcpH3~1S3U3KB&RH@K3^D_!H*oTfge*gVX$C-%!eQI7#28RNbZyG513929orql*^Y~w@6$1lOgw5048&DR0tZaq_-GrtxdVuXs#3VW#3L&#Q7~7Z-_W!ah9UhzNHS*G^svHH2Tf_J*ZOk-0nGZKo9S7rvithW_!AH!z4wTVy0htTykWtbKwI$c*&TX7ciyZ$aYylbqWe7Z!%#yqjdRz^$&7oWcRL25~hEUau51__6jC#tIFIe3XaymuK4AahjupNW0-nXhXCZq@GSLZ@xf36vyE1h7dKeBfA^BNX673te^MUzOopw!coDv$1wns-1!22*NWnmiZ27z*BXnK$1GzvB#PM_$kMe*luXLg8t^K%DFc1BwauBNquXl3N9regMhHsbpLb3Y1w9uo7reNH1$~F4rn7k-Bg5T~T0vWef~%c5T2oC6OoC&eX!E*Q-5@Hw%@WJ4Oo09p3juy@VG8PRTO-aGKoUO#ZH$OiEQM%2R%U_**TIzi9!BbbG4l-GOLsrG4*d9~tfDIoMee_CgymiBj&LoiVRTho!wuXpt~W6bmYk*~Mtl$mnDPIOxGbypw~ADl7V5Exm-mDOXeZSLYkr-FjKvkFHLbHFgxMmC~FmEf%^w4TBPddMae*@hZxKbKMCgyBwV&zXE#2$t_KUVcQ-Ar6GGGLzR%EH6F&OGvmk~rC_yRfax9^-uPLwD_h4BaVDKwMtTsk93eWjOc4gUWTiuV&BfC&6X69nt5%&zhb#gnfy&lcgX93qgsyA5VN-0#!qimvq*z4dGeNqzwOUEpVUFZ9_656HvSd4I7FJZVUVJrVorpQen1PXZ2zwB6OuFiqhLIqUYiFRjF%6G*RcqvjvxY5M8lm*Oy6sRX$cZ8Y_6URv#EQRnOU80yb3J9vY8yiMx#QS1ljkMHf%^R04Gw0T3i~89L8zTdSVWgG~Ti1UyJZnBTtSJO4lTa&fa1D6P7~-eyXFRwpWkinrvl_VVUGsAQH*Lat&8x8#L1VVp6MH$Dmw$jn5c-7_Bg~OyPpgFIIzSBDqZVjMT$4cel8#VG-lUT$sq^vf^11Q!canMdFSA$6-FdTNxXICXq#wGS&W_EhbL^oozjSiJRZRA%G-nMMu8N^jSowxs3L~9X4nOVPWNfAfCcIUoKb00*1MGo3xeePFdbt60fkTf0w!bW$Bgodt-fcSYXu3VUWxJZvwZFWBt*JTNr9T@eCYz#&pR0H3zj*k2S!MshKAaJr@o#0-Q%$K4SyMzYb~dPoMB*dqdyFk-psqAW$%@SxWDFHnq~b%Ii73B#nVHQ5275!EuCU2!PhV0XBKVM1f!B~*l#IvYMZyavOrQYUWi&RriM4KEcZfUzYP4LLMiOOswIQ6G4DG1QqdQk7208g!%AqrDuDOtyvZ&abbuAbj*%N9r@My%2v2YCqaAyvQVW^LEXKal$nDqOmyScPFtsCie#U0Rrw221ZXw!l#R80$&Bur-Xn2*rz!pa_gKs*&VR!u$VGl8hTWcx&cW*9Vi~C$1x9*isOQvyE~HWtpN4$-tXXt_jil~p@NLY$JxPjw9yNGIr3Po1UM9jry-!_QfOsp-LGiUY7fxHxP4RDcKvhusKxyo^wfzPmT$mlBPMzbZ6dl@&UrZ&bD5NLbUadct@J99&DU6BtQ%2-s%&1kjnXi~GUmkOGEds_$LMZdwmxd34mPVWaSSx!bA1W8tRlko7GeYJ07L~P4FQGU#P_zbDrX6XQGReLF~iv&qarznEkNbsL_bI0Dm%sBl%A%CYwmiXIdZ90ED~R&6Cx38VwmGS-9#qRE4b#ZI6%!uD4ARh9hxLsP#D0X_Z#ei*d!YAyWWI~ge!qsQl%OO~@EJs$l40@8&_Ygr*WJzx6zO6~pdnh9wqvGq7juS@_Y^du20aDfB2DBeI@q7Bk#zzJGjYdw8AHv%miyoa$E9tL%H5H6dznUlq8vgFzTM51g!7d6dicFSSt#acSz~cn~sswbusrib8IHTT@~oZyt@7XDd_#-fcPbbtkS~DH-hz@gIV~cX20oDBTxk@W!ukrYO~KDCQvJwNLHm4sfFJ@sr2lHY0YXx6M*qum7BIvQSuCsDNqOTaMoqV764$0&x9yNScPQQ^90U1uAxpeNgM-RjY1JbUHL3$7RydD4osg8RuN~qub9C2*3HTBUwmy2pVrJR6vq5!Jz@1s4ewU9q*^a#jo6VoY$rWEgOuxu%1OtvG7bxzaSWvi3wOV9F$kqPZkDv_T*xAsnyXeq_Bpaqs-6~0CN$2sjjOaEmvqxM78nO&q*ft@7f&aYb5LDFkFi4OU0hdN$S^4-Fv6Bl~qCUszsjSaZL6Su_SMbLtAdRmeyptQyUmr9uh0UPRW06-@4_2Yj&-ORAn!~CAq^^orv1l-I%gsN!rZxUT9kQCtkTueC#pYU%3yT5RMLY^wyYktDqU2hU4@Sm2jZE~aqt*jtEwHSDiDWP#KjZiCkE%gDXq_aqV^v9#x#AsSFWQsK*5KGr_4zj-1IW6$6h~yIm7~27rSeka9H&Z!$hW$gvwh78EK@b^KYwfPjiKaX6V#@xXceKn@!o0qDhdDgb2qMmhBLpOE3QaWIuUQWm18Xz3Xzy-al6rs!nSP~FEo4!tCrKMuV#VkXBHgDrO%o7mECZr0_Sav0Bp$nO%jYyfkXP-K5iyxv~#TJJ6&s7%UNhXJ9pwBIiWvMCpuwZQrJT#5o2@n~auf0ew96d7k%muNfjDOBfBMWJ%cxrwLpnjgytcsH6j--xEwJ2Md0^~$59*ImzkJ5nbAIREWcOX71nwjrQoxhN1akWG2*6X^kYL9TdwDID-oE9MDQJOv7LdsUB#TCAn5KJRV5O88P0CgZdfhhFta0ChyH-e06Ot1B5A-Jot64#z_an^la#Q0~FoimughGkAejJldwYQGrZe~olv1I2h^G-we84TVjA-&7&5nj~R-v!VL*sTGmD#geUB~4EJmR*xI$BASNOx9a%#$cCB6Ld!%GOvs9QvSA$mZe_Azuf@u#S^x_qGaL#pO-b@0-Z*xS$q^9y4T@6ZqqFBF_I3@zI9y2*w%HuEz4IYGLTF8_7G^hty$p$B9l@gZMQTJf&5_kR6H#ru%if!2ymQ#Wgz^y&M-bc*lP%6%ML$iF7T#Fb8Ozr$9BnghVGAoKOHYa0~@6SJL87ckbC@OTl$r&R^*1ptSi&N6&seFQEBzLi*iSjkcQ$hTIp#PUBuPJTFpGR^Rp%jJ9-HTeBMno2Bc9JAY$fXFISSrjLmyB!pC~wED*DGtWGYioMN*Q1B*uPSBusk5*@QH4Jmz123NArTBo1VQxMV7DU6jV##0t^xVeWB8Unpy25HI0pNd2HJ^p5!ecFxdqZDUC7McdLLwx3AT&lSRn*vW1P42Zy%-Kx2aGEMNt-Ff3jK*96%xWMXLwWHkrhF8isZjTMuAC&k9v-N5wBbc_*SU*3Vhc&yqS2f-dnSx3xG4peN$^aZ_-z&hIiKK^A63qSgCYct_w1MjNgeq@clrO6TjS3IoRys$l_Ax-gR0ST79rHG8t*o*-%4^BG9!vUKrk7zPUwypHZd7t4P&LSal2XMb8^tfC9X2B2Xj0AvgCr-lg2*%tksVg_UvN5IZR5S9SOXEZ-ByBc~bRu#vvN-JrXYXAUcr19pr9EK4p2SkFkSsV3N^db10RuQ5k9k6wNyXy4yE!9H$PV^#LYkKwNg$QJiblDZs#fnj5N7*g57%dhlDPNjaqW7Uiot9Y4#lSn@Y3*t^FlDpx$dzkQChH95Lkwez_WZjKQm@~tRO~B7%4R7fW*N~#U1vInHOKeANSn&4cgz*25-3q3HiNqEps~6HRm$&hN$M@Pb&JsbUunN7qN$GUTMvP1sWTRaY%J3d-rg94JDE%esNio5oRItg%b^!lniwsa9KcP%v-bAYjmnv3WrmW24%I$%1Hl$PHMnkWk#B2w%w4Pcji_6Of5x@nrMsC-VRBrE00ARZt8Fin82XsIbQf3Dtc!*ErV9*QI09sznu6xqUvkdt&L#QTq%I0@B8YZ1dw~endxP~9UzikBg21_r1HcE2ojrthvO9@E09e421x$_rMenW@fV#i1*0eUHzWV%8gLz_n%$-zp&1ftNdb!r$72V3KWfzM8ZVo4L8-0NEpB^-^XV2F_^aW&S31Is#ln!eg4Y#K9&tPBP0MRdkZ3xtA%Y7UrluVylJHe#vehlSJ#e$q3aGMS9Gff-LVP8N-~ivkI0LP&jsD6qrb#Yd0@UYbFqMp0ks5dPfZw-ezn1X6F*Ptl8dcTm8pco4HHM_~&8L$d10FX3Kuhh~jyAEZe@y^s-oEGIV6RW@D3c1yK~-kKoUDgDuqUm2S_x7_Eojli6Lp^~&aE&zTo3L9TgZp%IYyArl@WMW#GM5qqJ2VCeJ_RE~_SMq7fQ_lff$hqyk9WdP5WqLsEUA75DP76f*ZEXfi!8MuYo5Xtr9H~VTmnRwpsawzTif-rKhhxlk3-J*h5l^&1GHun~h&lxHO4@X*Io-Y@~~1-nj9L!hsD-#M%zF@!5sJ#kJOiBbS*$iV$kLij9FcVFHpC#5Oi~8y0f!&VfrjK5Ua@&T4RJDpoYxL9g#qeFI-fkSV&Nr!gy4u2@~9pblfJBsR8#G24%pOy!Jc*Q6W8~unuPJv-Z94ABkUf9g%vGMY4H2OBITHGuWnKo2jR4XkL$YAEel^G44sUEAo56zIzlQ&Iy%rpDdQGs0-KRLIWv-f*$@pv-!h2DzmdUFc1_w%c*QJSEnP%RjyPf$~fNibWbYjMZA%ni40En%Q0ILvmZSy*rxonvNZDKy^2b%ll!#Pf$tlP_iKtpgylAfNZVj~cIYR%cW6ECQ7~YwCWZsU3DNJDRdzuduDt4Rri#M_GCLwfDF^fll6eBU7-^1pvjv8G&cps$v3v4o%RAnc847U@Q&y!m*Qt0lTheTLBsNNM7Fdo&V%dNv8vCq~lN0D3&2AsuLbAWR6UZxUhGU6TfhgwLsY8NvktK~K@aczQPPE!i5ySkUhJ~U5F8A7kox5!IEZC9LMh&uBVZARJuF^nP2bGGf*98mIXS_&Yom$HrugMT181az%JqqarTiA49%dO~-CJ~AAICWemAHqE~b&J9Mq45i8nb4OkaGsB!X5OQHL35Oi-h4&K#d053&hncB!&7r~cg#T&0$P6JrH~NxnmLLiTU%^cC_5h!k4EU!^fixF024oU7!xkIRtSp29ONEI7PcOSxHVFs$FroluFCe42NHk#RXoZPbYnl96clnqAQRpAbMiNmw@9-Q0c47&LRXdO-CK^Vm-qUGVH*LX97*faE0KOJvaZ0Fsuv-XMlZMUpatQWc*EI^oT_OZT_A&QU_quUljmBPt--ryFwCgQ%_d#dKQPFKwUuHQw0Mx&q!veW@ZQAjoS202AfZ44_5_IFAHjtIDpgjahHqhMy0Owct93_7rIEDP4oDPkz1cCyjJkFQOCOH8v5x7IKLjHsUiF3_It3s~f_R~ByHxgO8Y~V!_EgjNaP7Cblx0S$d%58eb8Vh-dq$MIbPBxX3mbzD3LKI9d128#HbpQVW&OjSIT1H1e_XjUfmws%bJJxYYRM60J16g^_BtgN8s7FseU-rrk!Qp*GdmL2c7M*PtTlC#9#$lKforvNcXnBT$rkQFQf6igNVTGXe8K3$3!f@YhlJGH*fIN*rz&8q5e^Ia4auCU2h8YK~u*b5&@O3&N1!Td-PSs@8d2ZflJigy31VL&anfNwZGf*LrG3FWzzEXf-1J$2h9p$Bf62Q@**mAI%-1J5e1_!WOlhTKXj@^*eOQLHsKm_*7Z75YcZI~aNaySzuBTU^IemMp-*YeuO4$J4o1G1*MkP6UFoShTU^!n-WO_T^yBKHuosr&fxZ0u1x~4Wfr1HhGeR8Jeypx5zQLBw@&7XF*HlAKJ#~dzBNS^&-*Rik9jINcrY8rkM4^rBoJw9y_9!CcvqnFqC&*5yO*ON6okx7vbE2x9oa4-TDTIBT!sAZAG67YXcaUeSUb_c9Q3rqrrnBU9k#DNHJq&QnOomC9Mw0Fl^lNJ2&_fCZFx$-MGKO3@U@_g93L-MACrDiIF_*H6p!hs53UE9okfa%O~TD*he8HlGsGs$cRLqfq9CC$qp&hgDxa4VJB2JXAHZ^8g7k23is#47GoGyWe~1fDe3KHM@@n&cKgbD--yShKNZQMnmiOIgtHKfQDI6wm4Y&@iQm7umCq%X4M2zLtTPhwv!k5KlVsua_4Aj!RF6MEY@C-$Aou$y!$ypWFiL#bZ8W5SUQ^mHN0_flPIq2uOMPI55NpVY^X5YIZof$fBXg$Pukf~hsaQrKcEY9rtz0-BaCGVNhFHXg%Z3nll*Lsru0l!V!cNxPDLSnXhShn15X&QWxw7Z_cHUvKR5qZs#LD_RB4CoOetBrHw^j6rn4@j_J!h#-@62uS^~VDST~%@wQ!%fQbQ-@9u8#4C$7H#zSOUw8PtqPvXWK3wo#*E~kL4dNq0zPaQ3~EwgD%&5WRC7jAV*ONt*&H@rV0vA%PjNiXZ0yg49wIhiuGE@CvAMQpKc!zsafD$KCu%VDW7*FGkU7T#GDNBpf2CxeMUNA@-O!lGY&MGG$DcLAHqIhZBRq#u%n_V0SYIlN&JUr4XJBW!&gU-i6^&hebNJaNa~2m@Mee9g3INhE2z3v9NhZz&P!r73j#5@2CyPkL5Nn@msZ65IyT7nf477_r5xWllu1iJw14TJSfRo$HXX&AlKvyrUaxAkPP~D@jR%gJ6n_3DPbi!FkTlqWi4U5#PwKRMVvUT~t~uyYQH%pDac&W9hfg0XYc0Q3l--ftVjgufYv%R78Plgh_zuL6&ePJZre4UDjEM*1o&56c252dRxJ@*lGyhDv5fxwVfaI%Q$K^NN54AJ4UeVr7vWSEeff-LwiNQSwFGxvWQ&zhBH@$Q^LLsw_cZ@!D2&vQAofO#C9bcDvN1H9PxFN3hz$KDXFWkYoCg8J~^#HFSJcevb1P1b&opPwrHP6cqFS1*@eu2lpfs&P2f4YU10EnQMrsTYNFY3XcLe*K~6R~Z#suLVc34ZsOd93kW_7bA#UR#h^anX%TKh%!CtHxXL94h!!GFMx*XrIip7K3OJfO@Degxn*&Niv*-a#i$oA2&QLJD8K18Y5U!OPQBsMo8grbQgP1iqL#TFPoEt3egU-csVuPLBRZu@bE*~R$8V-d8B6NN9e4yPzL68#dv!fQ7TeWTa5kIMeNoLs3gz1FM&CG5b5uVWZAf*p3mQtGe%&Q_Ds862$OAETAJGhkx1s~mtAaOjEQ_DjqB%s#V1^86v^mSedHd8VWqCa76%*VvRl&RKEHp6974gfuDG16e7ht$p_*OepEXJMfvw-_Js_j!HkS&a%sSRqTRI$iIbap5!dxDxpm-yTOGe*OhoM5aZlA3ScQhMa%%mip5*TCiJqFcjk7@w2QxMY#7MyXn2beVdWTG~glN-WI&#1Rus3qNjTt2prE*@hepmwvQ#-GFIgUYk0NX!gnX$jSctxr_J^#r*K4anPvhpFjXSw7iktTg1%-H3*YKkhw15WhelWJj*ZfU*9N&wGbpg54y&@jueAS7i*iR^WnYu@Tg5-ift8XWIh~bdtXq_pgttAYv%tqjqgmVsS@mM~@leISq7&suskQ&djdgEHhUE%SbWEw~kOtY553e1FC&FM%!W2ZFQ-rpgj%ePeQaR!lv5dDVxjk65ODlJ__rhGgwW_gR6rbrDUu!MSYBxEj^K3KUt!o1jovf@_^-c4XAT4S^hE%eUPP@E4QJoKXy!JJMGmKaXCQz3~W!@pwze$97rtGJu0zu^A!xWb-GgQjCo4WybKAqywxk~HR56FEDFSd7EPO0MCYzqelJXm-JOMxHJBugNDg-O2htQL6XZ!8Rk56LH#lLYg*zSuS-JOC4lad#llqBg4RJjrKVImyCr~&nXeKRjID5Xs$v11uKwzkIY&x9%V@xZRme89#37^sGHu*MfH5gi78hYHt%pTKmJRFlWVMec~&t*dFq*_ep0bIX7fK&IZqWVmX0O~~E8C$o!U2P5M&qTDS6Tl*D1oGO~pOp@3Db*!VrywmZ5GUQJr#Wgn%P74EESGLn88sTHbT$ZHSjYTcm7$lqmSvk^a&uCQBzp2tJlu$sw3yGorxLXLCIl!UUN7KH3yWoJerkHjM1W-NgOHiSVAfn*7vzfqBC08fCTd&nI@g-fRg@JX7BznWyNE!jbUof#eT$JOnEuqUPXriTVAr2BM#4wRZBJBxD_LR9tVmg%hgj#xf47nnBUXf0P8uH~k7ZCA%M~8!#7$##EJiaLU_b8IVEdiYLon62@^re%aTuI!r_h$4pXx94_srpwT57IVc2vIwhN6XPIFImrfN0GIbnQY!B4mQ3#VX*G^0JNsBLCqW3&EhWj7Ecz!Bap1ZkRg0yrCX4-t@nDcoO~sE-xPAwZYYoHZSIYE~nITdaB6v8bqax2urbpxokBu#uB0i&T7yjszM67J&3Rkh4sC21duibTNktcMJV9rcsGsvXX8KGYfaCd~P4WmjI1UgOHlJ2mdxHceD@0K~2&HdqNocx845qE8k%_5~BL$m7U88R7-5Z&N*!L~eSoZjq1~Ek54L88sX~jebOzBv%BYo5eK2fjpT_T72kwzx07f21zAM~MnQs4Xe2ixG0Ws^KweujB5UA&Za86%03ma#68ZyHNuQCsu~AV2lY@OggjBDJOfEZv1HxctGmjuK_aXZGNhpqsQ7vA%RyjHpCV*E!GrH6mZe~6AaQ~VYvNqnSp2*MUuFh$IB0$-15Vdqgy4E^P2~HKscXHqKC^OtRkVR1g8EenpDkVIWrxHT9gL%tKdbLSNTYb^2115yElGm&SbFWTAPxZAftNqw!1nhzquUWtZ5V4w9nXpaxIC~VQF-qTz1YVI@#RkfpnD*5Gg*luKUsutyb2nxHmqYUR%yLnDeS87hdJr-$BbYjEj*_N3FKrYGj_N&s0G2DOOIHfxux7~!PtzC8$CPzLcuEMZM@e%1HEM6c%9uK*7Sb-J7jjMvXVnyf0yuedWsbOv0RQe%jLtFliiV#G&54Ibj59xW~J7Ps-~FlzBYQ9x$rjfhoU3G6yP7AHJNV^WBfp1b7ZAoaYtO^MiApyY9s&3$_uX_1wwsS6C!4k~kc1J$2X01thxo_OnC1~-e*IZ5g6$keU7dNffEpZFY&rh0@SgaR4l^ai8!a8w$IL01ZeaZF*~olr21t8p!dpT6SvqETT2!7bIyMcdJIEBer&KFMkpe6XF~7hfC96_CPNc*jyZ@7-9#J^63uamaRt3TaEhyXdn79xthVoyjLdROZPW8&JG0SJOLg0oDKnm*c3m8T1NPP&Im~B*NEnorxClSqlmrig&O~UWo41$N*f@3PWTYw1c68SsLM@_4eBO35qD6%R!$g%~R1mH_7To7iQQg6yAnO44t%Rob5$&rxC~_0WdxLUs7QIO6SlSDV4$~slR^fFi34wAXspb$Cpg_do&UYbECNeInZ^O8ad1LgMw*Q^EXTo9_aSKN8nmfNON7mHdv3EoGiQtl^yt#M$ARxqgoa#qesL~7OOYqxwQf#PfzeINVNvwoc!o_pP-$bjV^%aCe$TcpkPc6BYWomJd&$X!Rz4~F0R@WfZopDDt%u*JzQ9G$ff3~X*_8w8!C&81DeK14tSwCl~ay~ix&ml8Gfa*4s*$N4E0Q-IfjBMxBMFn~sp5A5Hw25w6d4TKq5fObqFeNVwvM@XEVc5lF1*!cRMs@~t_Rh*y*6t~5m%@iacB~Dv-A1*PM*QOtcr0DGZ^k20z9mU~0l1yC-kJg0ufY6rP1J69n7iVeZAcuB43hhVnPe4jKzhA5tGiedqB48hHmb*Mm#5~3_dsoTE%0~F8OjLdL7Ig5OC8-Wmk3RgeKo%IUFnTJfM5b9pbdTFc5A#K~*mlMISuROQtj*Q$qWK85pvZhsd7Z5wM0lZ9l26hHoRmilZrH2i~RvX$y^kn1r&EJzeZemmbXWitgF-EhZtJCGIZ0ionSRzQM!gjZ201OfdJmE2W8imbO84oc^FZumjt5_2K4xwbPQhlc!59c917j_&oZHHkX4V1J^ecHcNeD1ECs308GZEKgXKL%H%Xl89@DtavazCND$X^TDIm8~L^tNBiHw6HvF%LGmySyrn$aVG#_w#jkeE_9PV752*t!1DXy8rRDTF^9B_j08~R!KVvD$LByZ!Z@4nm4gN47lkS*e8%7nORzc#BFWqSBGWm4bb_A5@@nZ1fLmppb~OJ43iZ_OFqo^*g0fK210XBQgFzDdlRIuE@J6xkL@@W68FyP@4-P*ARj#L%1-d^%H3tP6~aGMnMUqODYQMx9Wbt2vcRHx&3v_8ul4P8hg5Rx7W98%khD90_sdRI-k911iTJzeNlXBS$8Y2VS*$WnOhn63A^v@ILH_goTgzlPjQUHyMcWP0NjxB82mOk6Vnmn7-M~PBh_Qt!4Kqf72Nich6gcSjPKBi*mBLUA&$ttpvRlVKScKyU%IEG1dtL$~#PprVV95*-gvIGxs7JE7AtUa~G8~O^-~2Wvt$YdVBXFabOUq8KHQ@V~bH#_Ls1djm#cD8y6EcV@19oXHDkqzmI$vPnZvp8U6ue~z580wR&ZT6_4PF%UmgTDcMzxB*^HHv#$nByTGVhY5cnvFrj6s2D18pE6sKAplN5if%_Zkpq__qkpE-diz8!PU^LQC^c0uflHT#e0oJQ6^_KTQYKrgG7scrz@6$qp&5Kd2TY44kBESnIUMRmfN6&inRETfaO&r^VLLmS@^LxhFtvAeecHKti1!hkn#1Oo^n^7rit4HTDuL!_7Ny8^zWJqy%XLB8p5ovkx%YGlQlR4AluXsf#%SPKOMI2HUenxK8wlig*KU-IDdB_TMG3EcH#3Se-_!fku*gAD5kfa%hqEsZyzpugy1SaY-75p_!sdvo_uQ9gO9R7yCP*MmND37zlNm87rA7W_EeNKs5Jwz~rI6v0qU@xOg%dNF-7QxM1nkPrKGSfUUxoFkA7Ydyv-_sHHgfWl0jf_mgdz48vk-4#5NW8E!YJ*yAaoR-BoZxB*jxs@-T@$vyh6W&UZ4Et7ge_CXy!!hSWo6iKAmPBfQmEv4ZN7f_bbY@KL6bUp@9_nJ6APsgX&OU3*TIAGF#mmy6RSX%JwJGU8-pEOuKoU8ZPc6e5wi5iEr1l$8tXfKq9HMsIo4d*RHnG3$vV5l39uo2U0qt5R6ka50cRx$AoB3#WGvmLxvvHTVo~Fq7Ihi*~Z94iy8Z^dX5CcF4hEEt6JAi2FS97d8C^!K^6dq&0#U14UuK4!vgHfAXaM2RT6tvFBRcr-$5S^POLW2DMCqhT6^Alz%9GCkxXGMiCA4R$D&!F1X9fx~G@sLGLRSJMTxFX#_AQ%nmKh3hxl@~*jNy5xL16T@*d5%RJWE-dAQtZ9X1T0TTA1Ae-e4aKhPqHPYjyGXzyt2#Y5jj#ue&hd6*wfnz_S8V9Fm7^dM17*5&d-WN3Ak4uYL0JzTImqeixFAaT#zqPqY%NZAe2&tQms8EOu2W3AJ&$s*RgLuk-Oe$EKYM~-~$6kAv^QTO5Gtq*pbsO13py#GEK9UnYri&IE4JkKRDTimao-LH$yZ!SPlnfQA*le6z&26brYWdj-SPA*y5R!#PjLW~FSsL6a2vxauTUI$x#F1GZD%@6aKy415^KGdN92dN##&S1COFXxvZp$GUA%_9Q948hX!Kx9zgG~x35pC5jZ_dbMo@OmR6m1*r43XPyY&fi-1*Wbo2J2ugNLzyC4$Ij85cm79TPSypPG3hL3yDxgSn%MJUG5WreC1#5JNTG7IQnq*-pcvH8&Z-wdxTu9uB^bsngVdbcHppa^U1WbnJJbzc8Crxy&qdmDVQMN9h~IeX*gCzRKJwu4RhLTut&chef-5at9rRl$~AMMivv5E1MP*6EF*k&nS&AIqoac1%oQZAhv15oHsXB*t!t3!bdH&dyDbJpSPO7V%t@&GqYy2fZMC#a$S#Ts%7YVAkAuIbCaiB95*6itE*gb^nDe#lr$W0BC_xs1fW@7fjNnY%HQM7@0EvNNrwLsAX%Ae2vQm~^-dDSgLY*8jwQ%eJ~z~KfOFDqAldkyu334l^dznOY9YeJ05gjdxN2Mv&-UvB~NkaGzi3%5M0qb#Ez#jZfjbJNOUS%6R@@&l7A-M8I43!N1gPuHTY!XlS*HT4-er8-6$pX1ST_OV45&Uk6zN7XVg8ls9dpXlz5Dq%jvD#MYRtlA^Yy9-_v!f@uaFyDKutHho#!As8__cYu&r@h6AW87U9g3bmz-oPZMQKLmoxI&!jH&*LfQl@LK5S9T1@F4u4okmSfUmVO%xL9NMd#fh61B3h%0f&06OM3dS%T*jWG_wUOrkkYTh_&UPFJ9SvB$OsxgrL6ynh~JvpDv82_7a!OHJIWv!vdVDHl!#-$lC$4WbCfpG0^6kFaQ_90M2PStrQKqtew6@UGLyzp4QE*e8H1V^lR6nJ0Ac*ebR%uo7eV_IXSoiXmB~cd9800fhG%YOHzdkIr7J^x_j3ATBgKUhs5s5Hcxc39AKDzxo9s55FxIc6RQY*QatOXi7Z6bpRt6-jFNN5Hh#d&kX%dq#0CCa^YyewIBO@KFoVsoiUy~geYl#yd64tE0&CHI4fv*ahez3wUFK@@kUExzT^nQh#oT890RcDrc%lhZ4ub2WQ%i*Z^t6xJkT6xq2Vma^NNyU3Lc7vkn%Wo88wALG9FsC*&G8yOSJU#$mDe_hj4@YYB8zvc9KW1_WX%azrH^oQbaW&3~-n_sNB5@g!D*#VS4Tu1sSLcQ~TQ2y5yA#bXO6xuWed#!09tX9oGZQKBKx0Htyg0UQ-6NOLne83*fh6lIODSr08gZ28FaU_GL4Yunt6z^Ma#EV&YWMwEO2KQmk~npJWbVF*4*TUpd@ifmyoW5QiEaXgEj7Ni7D9yfCH_A28^Zsr8nRjCx$mDXgQce5_WT2RuaKS~FGJw~-tjjPgbv82SbGErSL7pqq8j0qqY#jP!tFAtLKZt&Zrz*1D7%jjzb7C*MlyhYz$&nTAt#KnS9_U~q6Hf0MDx~RPB8SIP5q@MCBUYdb4!hH@Kw8ZW0jHhcov@QD2-!cY3m@q6Igpxk858QbePVz@7ZxrDUKa98$fqYvD$qbsR$LTqR~RGP8#8OK4%rOZ&6nQ1pHq9qRLdjQvEDKfJ9^2Unwr2~nmT3mWd%0#R^Z5EOa5^4eZNRz~&1JaGO^c42&ofNp7RQzRu0mm_iZj39l%%JqXBA#1&CaKMHUkR3woDia*lr$FO!~3-~&eVzyjQjgZaD!xue_b&X3*8w#&WjxO~&RF*#m5tuTGOoU#Y7t!7-*q7ak$I*ST!fE0WZBhMQ9zHnQ^VG^100i9yw^sQh3%vbSwpgWj^4!-FQFxp&bTEl7jhuS0_db#pvso5tq&~bv&k0znmNCz-NRkSRCzpBWn#y5l2Bc-N&KVTJtlqFviwvBDOc4Q#s6S63@j$X&KrxCh_QndJ$ZCw#vDRdNAa5B-OmS~sW%87k-few8ioPnXq&ts5N&GyR0fcvOmeze~fnsLWEn~n7wnhTsW0zl$fj9p4iL@lnyDR^1-wcVa4OU^@W!YqBHMK9gIQPDEV3o!yP3p5N4jkAonFnUN5n#dIsDYSuC%#BmTwzcRm^9eFVkX--lA#T4IF_-tSg%b-!xPsX$ol_0njAC8!UD&xHTM7m^3OoF^fjBkOYTAzvI#UjbluyNAOGsTzjGhLUR_WJ-n4y_ezb%Sn3yL3JRGVY~qgZJLBseZ^b8xG33cvxf0dfX1&RCa$c4@!YBdpArd&4Stg%0mNS#EIakWixD7$*I620m7hM_1-&cd0#X$l3m%t8LQVqWy*oqq7WBUKXX9663%*Cv_dZK6Y#srqn4F4RvQf~Mr_cU@DW^nmDeNK$y04jHtV7!nmH_^euWta0brfa7@__UOp6Xo-qEt&Po^Frs7$$EHYx&5Ki4G_Xl8mHB!qGW2FCNyLRhMK#vCYhWMyK36t43Lp-!i2LPout39Y$rT^pQ*DS0^re*FTeaQOSQkDc&IrYMF%!y4mbOsddHb!YbdfRB7vxGft*@pBtJdjYVFyVGyCkD-BUu6_@T@J^o_q~-np8tLmEL-pQ%BOPswx0RQMoC8N2J5$@2APQp-kjOwmk^pnpkBueW27cfKdQUn701W1HsE$%xnyxqr_%2k~&iTiiWUfuVbLzfd49DvaExtWlcDK_sHkMIR%5ma_PpvGxOvPLK!sqvZUdRkuePhenRcoYctkO$dODBR7ESuwVcwrnIPZhc~oIIlr2NSJUo@5QF@@7KorS8-X7zxlPdZGux#z5Ytl5xt4!hJtD%x9Q6#KDTEMaZ~#Iz!$XKvQ2pHqqZqBgVKjEr$hI6SjiSUKlUa3Es1OPHbJIe2qnZtlQ4mTm@O99W*CGt5-aZ!5~iID*Ztaw4j_f3O#vJVr!kj*vmG#Vy-~wh^E^24Yl3*2Iep-8HnWlM&erOI%TE~XNh$vXxcSV3Dy1!IfXd*2%h1x-fGMoHF*^YzUoe@A&szL9MGuaw^u-n4ig&e#dYv5Zkr&jA7p4F^i4Wq1q6_i3T~&YrQsyq5N!NIvsZ~yUxIXTxbuoDB4%0Q@uJWSiBLOUJ#Z5UZYh2JOwdA39BkpfJxnCZ4Om0Nk1Sq^Wt7_fJYSs&KY9-6T3ckrw!Y$$$$LSNM&m*!rf_ec@dVf#&Z-^7fLJH8qax1SID-yNCtBEkhpxI-5JgK#6CqmAkI@B2*QjvUExnVnrp4rmklV!V3bLjG%TN%UzlydHE_xUYUj~!GE#-lHfaVWC7~tmnT5^y4yhS$xhc_Eyca5WyTwuhmH-gW9NHxpXkE30r8mZ5xcpffMlf5RVtPC0Nu2$*equE@wBoTDz!-k9lBWisKlg2gKfMO!2nze3dRMJ6ddAgg6gppJ#&TQNVu2vjVe^7cqOBuLDWtn5dwmUsMq~wErb9Nzw#DTQDJv!Ax!Ok1TI4kV$bVwJ3CfwPt$dSFHP$%WF@psI_T!YC0aRjj^hXEC@VVro@xeq6X!^br_tau#Zqeyf~FJN7Qve%5CBYwxO2#EGRBgybTFJeE-qdbcEEV%D$5r~5lo!Gf7dnZgd9sHeNmuJ^hj%Ck_M7ybMUdPkh4kepUvN6Tglwg@zc4h&k8PbwZ-M5ugyOTW@Cd6ooyk#XZLso0S_h$DI4gMxo%trQhF3R5gT^CVXgF#D5*GHlIADIFid96Z9zu1Ss-3zZaVbYy7soJJP^PF&45qhSt2MS5$XLJgs!u91gS-H3$yZifGaCj~_E!~6SOu_!dgqg#vy^NpNs&wd4PS*AwgA%RX_7$K8twTQr4-F1&WnyyB7^b9o0-7EKEXWKpU0CnotVPXub%4lJzvqEvTAsZQFTpG-^jc-au23OV1YHo9gg7JSKL*^Mk@KHV-&u#FtTPTXli0fY@3^Qp@yTyK0B@k4Iudk5x9jI%bXhfXpLuMCBgg3ACSmC9E~sde-QOK6@cLxytID5*XJV@65A%l_NF9j2NC&Fhs_AaJXDF#@ncq$4#j9ZQBZw2KrcOOkoOUSLH%pQHix#mO~NDZqh6Z%T@B5YZK#Q_kcIkT89PN#uoHA0yGMrIe93P2o_v#lnKnyu~fEiAYLrJyOJTE@s1vAqeYpXUyJsz_9MEvJ3e8yOwJ2g$Cl2DM0qZtUOwUFgIaQf%2x$#_56ku2qqKOUXXtCOp-ZJjzRy@3T$7kKX1S#vKiF65h3TOhA^nKsXA*Gj3FNqTm6nbBLn0u@qp%-D&wx9~pYe&gj_7e9tvIIOU23X1j70pX__ZsQlIL*&%t7G&GI9uLzoMY~Fr^jf_^f*^NR^MC%QN9KZXuNjcYpiA#i!TH^ETHjC*_TDt1sqp@j_jyQhb04GujCl-MFI~dsHMB8kDi87#D@bwnUhA_PoMcUGBTBrNN1N&MDrnlkfj1uy0Q2nW%e#dENrwes0C0CzOmuiKGKwY~D@~x-2x2cOKuPxO^xncP0GuiWyIqiI!1H1GMbaMV0$SemXtDH!8R_gQJViPv!N1Rm&9RizN8OLkPaYzkZq-ZcaESH6&CtCTFS96mZ0$MrHL$I*_1G6TX5vA1ARNV45RGvsxpYQIDfbL-MSp@UKYGkh^&^!owgg%mS^t6x2pj7@#Veof7-#ZU9C@_7hn-D8Fk0_YoN9&aGEwN3m6C^Ayr@yeQGy6kMGZ-zjix@V8vyfJyVaBOO~4NX&QyQTtKaG!Q&msKKnUw#_U0NXrAJbzXnWiu%Ze@tZjGi1jxP#yE6KbT&BLfyYy1D*#abBPKY-bHlxQIVMa7SExuWgKbkdB8JUO0g~hYLzy~trLv*8hgyB*742~#9OSAzu^R60PQ@cr6QPH&@SR@2!zDRVabjFPtXzu#Ue_7gRh#S_EsW6r3m33WBhVEV5HH&@4!^qwhQ@~n%r$a~VCrHQqlGw*QrnJ4nzRDYSqyl16uevpNK_ja3qok1Uqc$t%~cl07po#kKL$&c$eY2#pia40w#2cM!L!G7K0WTFOEy^p~t9gYjTgb!XpGYDZEKYjafcuAAralGlcPln^PrrWw$wVB%R*FFmKT4xkJeI05uz!V6L-LkovEy@D&4!ac4*g3F#4iHKuS!A@SjY~1q0j36cTOBNM#FP*1RYjl2~G5$cJGB-2QdtnJoU&mJ_DQ90_~NZV$rQwDQUQ&CQ&k!SzdB@o6EFPgS3Q*mpF5Rq#XVlPYd1&hq%F6ELY&qw3$23fkV^J927@$EW0gmmLoMA$7KaY@VC46kqh##qAro%GV6r%FkcGLU~aQowSDsTAPHnOpz^14-9998sNZ1$H@#m8dC~#8^dLi8Bep#NQOhnWjDnOgNH6jZK@010B7a^Af%yd2i8ji!DYo~FuY%QltzExxXUHX2RUIp~x56DHmWxZaHwM2lhZr!sd*E!p7LZ0^XG4yZN6j7zEoj4cYOfnhAk0i63gQ*AMhfBhH!UtlvupICA&be#VdfBQFtViIeJJ~wSAuX0slL!ygBNf^KFZ9wCcRc@*HalJOjv2IKwgVFc74HjMv261Q-7A0mSFujGue&gv^NKxvTyAv@GnX~jLac!lLpj%LyqKup0%UFCxahVZAj-5A$K!y71E^fyctlVyY3~GOmTiWhYi%wx2j26xbPeFIu4!ggC^HRIuEjcz6D71PJKwiTT8Jv_9W-@DGu^eNOZqoV*Iu#%*!NOIqj%Qh$*G8SWXuzTKKzh*Q0dtJQvY728&hbYN&Rkn@A4SmcseWtFST-BScJWSopSG-HwFXa!5Nvti$3RYFpN!xVt7&ACx$hj~^NJUzJeUMCijdU!V8^j@cvz7IoS45IZ7cEl~xvvf!5DagMh7~Y2#FqlmyqE#7@QR14di#HES&FRl_v3juS1N%E#@W@v0&oABvhgxPS0phTx6zmE1xA-NWu~3gqITjwn3ezxTfh1^V_Qf&mi~bOISrwV0tUBC#-dxMj9wwRR_deLrEqA1zsLHybCpNROfL6TsihUuxKQzg~ydKjkvvKGkPtRBgTjdlSxIFW!CN9LKtH*Uod_wPyWAr^fWd1OhaqW&zeqOf5EUnHhI^_APOfTd86Nz2!KDU0WYcz-4Ss@QwP1wvI4-9-5Q~T5lF59u7VkrIB492Ww4lxmO_38ePkmm0aDG@1X936iL~qHR271isFANO@qEFScSl$nXT9R1ER~fWBcgg^5&1NYb$HOEe65X$ELKcQf91^AeJASE0q7ttunXgE5iRRv0AmGb9$se~1qpNdkWs*LbOPV$TkT-vtSvnH9_^y@r!3k%y#jO*#I*e4WGZ_RJ5U*rQB#fTdJRoF#~64!KDc3~MX34SgrEPTh7f^KPte%N$I%tChgr@zITJYf7Q^y5GeE1S5dpIg9u^$tlLOZaj4S33%zndN@yEZrsV!PAjbbvNTslu0okMrMRSbq0vlQs&N6QS1Ng12Lu8e9rhE*GgC4#wSNzlsb7D&v6mel0GUR!x5AmV80$#s2mOn&NdTxeBg_CLvIpMhoDoH39Qm7VZl1rT69F@gO@l^a5iGXC#h1J0%BlwqJxDIUsOQsBxehhlBIrb5meQCE&REg&pVrkI4rpwm6IuzMzV~vrYySiIEsOjvCQ!L#j^UbD8HryAiEgU$rJ1MjewV#*3K0YWI8nMHnBldX*KFkA6pg^HXymmpdy^&kwdxV2Dd#^KxDywad_aK5cH2DvoY7uBXe1q*KuRHIowD$*15B_hj%vt8C2TncC^@ZWYX*D7E_d%jUuQsDPbxsaqXE2^e5zQn6*EQyw!VitDeu_K1r2!bleG9sl0F6eWI1WRoxfox@nW_mrPS@l1~&0d^jTLJQEDpuWYLiXt8Hia54E_e7YIu3K_VyF3zxP#~g8j$7yr$WkIL!$9G@7QTQ*GQZwBCy8s!uK&WB_fkwQZm%xNC5hQ_ssNnDp!7I3w8gV@Va1@n*UpRuT$JzLHQnOZfUSX&B6JzFA#M@EA8tRMM^0tVFZ6bewfZzmc%HPD*Uk3dLBqpk&Ju-J4PulLLeukeBX-7*V#d-4cI35R7PXyK2!F&Mjxn@8AMwUZkPqncTvH_Z1L$X0lsa9HyREIwyhOOcY3pX9kf7s0N1yHsML1jXor$4Qb9xkyAGSkC5~eH$n-PWOyc&_DXDIqXf^fgBXQ0g1^2YGIRRv@PLq73W9&@0cZK1MG@zD*yyrejb2$Hz$yKaoKMW&8kbqQ9I&N0Wsg9Q$e7pYoqqldT$22xXuFyXvI7vj-~iKh#EB1u5F2ex3#lmTTLuX&-86X2mhs*0ZZYr6iU1&$YAd2btpZY%QBEr&REf-Dx_C303qxc#U*Ht$j5Ke&~6*stkU*Fd2pldd$xKIbTb0acC~kQIGHrftMc9vyF2E%ts*K@s7gKtZDuYoT$fV$a2*QcMroLqP2y@sUJDo*O3MxQ6goUWhOH^_sRZd5EXMRcj$6C^0%FuU-G^o6SYQlBHJKc0CBm3S$pa1jpaVIm&DF_Luan2Vx62kpz6zdhaz7^^RzulxJ1XVVBE9kOO&WHkXkWusT7yX1vmZCg0PVWQeqYN55msytk2tKSE%nuW1Z1n9jsDH~10pFjz&^Ve-$*~xFlbw_i7jRFpzbt&AR7pvHxvKWClOXFmvar215FHqR^z5-D82i#XqxYJ1s*Z6yUwnLYDA_K#IAb5H7gv2kOTilB1h^v3@8n#Cpy&4X9^GXGHkGzGAwOC6V^LFe#IDI3co0&QSqYj9M-XF3KyLVcyh4@ya07T9g&R24rt41WG7Hy-uT@$!9vVgnZ5l8AXiV6Zf-ldC6pb!5_OSL#zD1^Qc#2_wXPtVRf6Ddo1pVMR_47ELTaYm_U$S@eGqNOO^$ajAzVPND!R*B7heGye_4!bGPRosu$lp0sKtJ!#whnoTML#d76UYCK4Qzs0VzS61@QZMs^owdgxV$a*FO_PklT_Farph_ancV7MK%fSn@bp6z-qicdzV4_wy$C#*L20i6@S^KZx@o2HNpXKh*sDQgmuc6RcHREC2!yzSv1!NjQFvdEPCLoBP0LRFs2HEHjB2&1Rz5q-a#W*-!iVRhwnl-tkMrHIw0S00SbPSBZehy9WgqQpxO0-g^NWu~M2LqqC6SM9jx*dy_wk9ub-Tw_DRtQ^*GP11AB231WufEskztih~jOiV$@%WrsN$rb4#Q%7bIpf2Q~zQW^u@vZf^ZhfuoJst~JsGrjYY4EzY-yqMHh38hH91iq@fKL7WQ9C3r&BS5Yx*eh%FlKux1p#TUYHQ_pnaZZ4Hmosd@7-^^3St7rKcpb*EPCytHFqDdDS#57@09OUXybpZF@D61#DODHgXqW2u~ZwxUdx2Pz~D11D_Yf%47pO%A_cM_DzCi~tsVX$I~t3hWr#t8MxQEC-yKXfp95*Rv-Nfmv~yY4mMHU-pbVigtD0d6dwmgMH&uO%@sf^%7afM9KH1-8A31mGFQ5bV690V*l-d8P*T~xnIpFPZetr1muIilzDrUVZHSL%J1%hW&!t*o2IgFCdP*x#QS!*qKw_WOS#jeqT9k3YD-8RH~5IrXKsOmuxv@%bP~4XNNOObCUUIWE!-cBT2LH#xScHNb0ZTQAv#iprP6YFLJRYN%@1WiKodOxUUKNnDIfCo3aD9TZ-vqO2^B1nl-VRWOkxVUmU^9tnJN!&14GxsTdl6vl@VYTW4C8yX4vBG"

int create_tap(char* tap_id);
void die_with(char* msg, int code);
void execute(char* cmd);
int create_tunnel(int is_client, struct sockaddr_in* tun_addr, socklen_t* addr_len);
void configure_network(int is_client, char* tap_id);
void manage_tunnel(int tap, int udp, struct sockaddr* tun_addr, socklen_t* addr_len);
void encrypt_tunnel(char* enc_buf, char* clear_buf, int size);
void decrypt_tunnel(char* dec_buf, char* enc_buf, int size);
int parse_if(void);
void hook_sig(void);
void cleanup(int sig);
void help_exit(char* p);
void display_config(int is_client, char* tap_id);

/* important globals - don't touch */
char UDP_TARGET[16];		// server address
char TARGET_CIDR[19];		// for tap on client, for target on server
char TARGET_ETH[IFNAMSIZ];	// target network interface name
int PROMISCUOUS_ENABLED = 1;	// default for promiscuous mode

int main(int argc, char** argv){
	int is_client = 0;

	if (argc == 1) {
		printf("Usage: %s [-c] [-p] [-h (for help)] SERVER_IP CIDR_NEW|CIDR_PIVOT\n", argv[0]);
		return 1;
	}

	int c;
	while((c = getopt(argc, argv, "chp")) != -1)
		switch(c) {
			// client mode
			case 'c':
				is_client = 1; break;
			// fake promiscuous mode
			case 'p':
				PROMISCUOUS_ENABLED = 0; break;
			// view help
			case 'h':
				help_exit(argv[0]); break;
			case '?':
				help_exit(argv[0]);
				break;
			default:
				abort();
		}
	// require at least 2 parameters
	int index = optind;
	if ( argc-index != 2)
		help_exit(argv[0]);

	// assign first parameter to udp server address
	snprintf(UDP_TARGET, sizeof(UDP_TARGET), "%s", argv[index++]);

	// use second parameter to assign cidr notation for tap or target interface
	snprintf(TARGET_CIDR, sizeof(TARGET_CIDR), "%s", argv[index]);

	// on the server we need to get the target interface name
	if (!is_client)
		if (!parse_if()) {
			fprintf(stderr, "[!] Could not find any interface that matches %s\n", TARGET_CIDR);
			return 1;
		}

	int tap;
	int udp;
	char tap_id[IFNAMSIZ];

	struct sockaddr_in tun_addr;
	socklen_t addr_len = sizeof(tun_addr);

	fprintf(stdout, "[+] Creating tap\n");
	tap = create_tap(tap_id);
	fprintf(stdout, "[>] Tap set up: %s\n", tap_id);

	fprintf(stdout, "[+] Creating tunnel\n");
	udp = create_tunnel(is_client, &tun_addr, &addr_len);
	fprintf(stdout, "[>] Sockets ready\n");

	fprintf(stdout, "[+] Configuring network\n");
	configure_network(is_client, tap_id);
	fprintf(stdout, "[>] Finished ip setup\n");

	// register cleanup routine for server
	if (!is_client)
		hook_sig();

	display_config(is_client, tap_id);

	fprintf(stdout, "[+] Starting tunnel...\n");
	manage_tunnel(tap, udp, (struct sockaddr*)&tun_addr, &addr_len);

	return EXIT_SUCCESS;
}

/* setup UDP tunnel for connection between client and server */
int create_tunnel(int is_client, struct sockaddr_in* tun_addr, socklen_t* addr_len) {
	int udp_fd, flags;

	memset(tun_addr, 0, *addr_len);

	tun_addr->sin_family = AF_INET;

	if (!inet_aton(UDP_TARGET, &tun_addr->sin_addr))
		die_with("Invalid udp server address", EXIT_FAILURE);

	tun_addr->sin_port = htons(UDP_PORT);

	if ((udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 )
		die_with("Creating udp socket failed", udp_fd);

	if (!is_client)
		if (bind(udp_fd, (struct sockaddr*)tun_addr, *addr_len) < 0)
			die_with("Binding udp server failed", EXIT_FAILURE);

	flags = fcntl(udp_fd, F_GETFL, 0);
	if (flags < 0 || fcntl(udp_fd, F_SETFL, flags | O_NONBLOCK) < 0)
		die_with("Failed to set socket flag O_NONBLOCK", EXIT_FAILURE);

	return udp_fd;
}

/* configure interfaces */
void configure_network(int is_client, char* tap_id) {
	char cmd[2048];

	// activate tap
	snprintf(cmd, sizeof(cmd), "ip link set %s up", tap_id);
	execute(cmd);

	// Client
	if (is_client) {
		// assign ip to tap
		snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", TARGET_CIDR, tap_id);
		execute(cmd);

		// assign mac to tap
		snprintf(cmd, sizeof(cmd), "ip link set address %s dev %s", SPOOF_MAC, tap_id);
		execute(cmd);

	// Server
	} else {
		// create a bridge
		snprintf(cmd, sizeof(cmd), "ip link add %s type bridge", BR_IF_NAME);
		execute(cmd);

		// add tap to bridge
		snprintf(cmd, sizeof(cmd), "ip link set %s master %s", tap_id, BR_IF_NAME);
		execute(cmd);

		// take target ethernet adapter down
		snprintf(cmd, sizeof(cmd), "ip link set dev %s down", TARGET_ETH);
		execute(cmd);

		// flush ip addr of ethernet adapter
		snprintf(cmd, sizeof(cmd), "ip addr flush dev %s", TARGET_ETH);
		execute(cmd);

		// bring eth back up again
		snprintf(cmd, sizeof(cmd), "ip link set dev %s up", TARGET_ETH);
		execute(cmd);

		// set interface to promiscuous mode
		// keep in mind that the NIC must support this mode
		// and that the promiscuous mode may be controlled by the hypervisor in a virtual environment
		if (PROMISCUOUS_ENABLED) {
			snprintf(cmd, sizeof(cmd), "ip link set dev %s promisc on", TARGET_ETH);
			execute(cmd);
		}

		// add eth to bridge
		snprintf(cmd, sizeof(cmd), "ip link set %s master %s", TARGET_ETH, BR_IF_NAME);
		execute(cmd);

		// bring bridge up
		snprintf(cmd, sizeof(cmd), "ip link set dev %s up", BR_IF_NAME);
		execute(cmd);

		// assign ip address
		snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", TARGET_CIDR,  BR_IF_NAME);
		execute(cmd);

		if (!PROMISCUOUS_ENABLED) {
			// set up NAT for MAC
			// towards the target network
			snprintf(cmd, sizeof(cmd), "ebtables -t nat -A POSTROUTING -o %s -j snat --snat-arp --to-src $(cat /sys/class/net/%s/address)", TARGET_ETH, TARGET_ETH);
			execute(cmd);

			// from the target network
			// (!) since this will forward *everything* from the target network the target network cannot access the server itself anymore
			snprintf(cmd, sizeof(cmd), "ebtables -t nat -A PREROUTING -i %s -j dnat --to-destination %s", TARGET_ETH, SPOOF_MAC);
			execute(cmd);
		}
	}
}


/* revert any changes */
void cleanup(int sig) {

	fprintf(stdout, "[+] (%i) Shutting down...\n", sig);
	char cmd[2048];

	// the tap will be deleted automatically

	// bring bridge down
	snprintf(cmd, sizeof(cmd), "ip link set %s down", BR_IF_NAME);
	execute(cmd);

	// delete bridge
	snprintf(cmd, sizeof(cmd), "ip link delete %s", BR_IF_NAME);
	execute(cmd);

	// restore target eth
	snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", TARGET_CIDR, TARGET_ETH);
	execute(cmd);

	if (!PROMISCUOUS_ENABLED) {
		// delete mac nat
		snprintf(cmd, sizeof(cmd), "ebtables -t nat -D POSTROUTING -o %s -j snat --snat-arp --to-src $(cat /sys/class/net/%s/address)", TARGET_ETH, TARGET_ETH);
		execute(cmd);

		snprintf(cmd, sizeof(cmd), "ebtables -t nat -D PREROUTING -i %s -j dnat --to-destination %s", TARGET_ETH, SPOOF_MAC);
		execute(cmd);
	}
	exit(EXIT_SUCCESS);
}

/* start loop (forward packets from local wire to remote partner and vice versa) */
void manage_tunnel(int tap, int udp, struct sockaddr* tun_addr, socklen_t* addr_len) {
	char tap_buf[MTU];
	char udp_buf[MTU];
	memset(tap_buf, 0, sizeof(tap_buf));
	memset(udp_buf, 0, sizeof(udp_buf));

	fd_set readset, origset;
	FD_ZERO(&origset);
	FD_SET(tap, &origset);
	FD_SET(udp, &origset);

	int maxfd = (tap > udp ? tap : udp);

	for (;;) {
		readset = origset;
		if (select(maxfd+1, &readset, NULL, NULL, NULL) < 0)
			die_with("select failed", EXIT_FAILURE);

		int n;

		/* read data from the wire and send it via udp */
		if FD_ISSET(tap, &readset) {
			if ((n = read(tap, tap_buf, MTU)) < 0)
				die_with("Tap read error", n);

			//fprintf(stdout, "# [TAP] received %i bytes ---> send to [UDP]\n", n);
			encrypt_tunnel(udp_buf, tap_buf, n);

			if (sendto(udp, udp_buf, n, 0, tun_addr, *addr_len) != n)
				die_with("Udp send error", EXIT_FAILURE);
		}

		/* read data from udp and write it to the local wire */
		if FD_ISSET(udp, &readset) {
			if ((n = recvfrom(udp, udp_buf, MTU, 0, tun_addr, addr_len)) < 0)
				die_with("Udp recvfrom error", n);

			//fprintf(stdout, "# [UDP] received %i bytes ---> send to [TAP]\n", n);
			decrypt_tunnel(tap_buf, udp_buf, n);

			if (write(tap, tap_buf, n) < 0)
				die_with("Tap write error", EXIT_FAILURE);
		}
	}
}

/* encrypt the UDP channel */
void encrypt_tunnel(char* enc_buf, char* clear_buf, int size) {
	// this is just a simple XOR - it's trivial to decrypt
	// if you care about confidentiality you should change this
	while (size--)
		*enc_buf++ = *clear_buf++ ^ KEY[size];
}

/* decrypt the UDP channel */
void decrypt_tunnel(char* dec_buf, char* enc_buf, int size) {
	// this is just a simple XOR
	// reverse of the `encrypt_tunnel` function
	while (size--)
		*dec_buf++ = *enc_buf++ ^ KEY[size];
}

/* create a tap interface */
int create_tap(char* tap_id) {
	struct ifreq ifr;
	int tap_fd, err;

	if ((tap_fd = open("/dev/net/tun", O_RDWR)) < 0)
		die_with("Failed to open /dev/net/tun", EXIT_FAILURE);

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if ((err = ioctl(tap_fd, TUNSETIFF, (void*)&ifr)) < 0)
		die_with("Failed to setup tap (ioctl)", err);

	strcpy(tap_id, ifr.ifr_name);
	return tap_fd;
}

/* parse the TARGET_CIDR to get the corresponding interface name */
int parse_if(void) {
	int if_found = 0;

	char cidr[19];
	strcpy(cidr, TARGET_CIDR);
	char *target_host = strtok(cidr, "/");

	/* following the example from: https://man7.org/linux/man-pages/man3/getifaddrs.3.html */
	struct ifaddrs *ifaddr;
	int family, s;
	char host[NI_MAXHOST];

	if (getifaddrs(&ifaddr) == -1)
		die_with("getifaddrs", EXIT_FAILURE);

	for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		family = ifa->ifa_addr->sa_family;


		if (family != AF_INET)
			continue;

		s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if (s != 0) {
			fprintf(stderr, "[!] getnameinfo() failed: %s\n", gai_strerror(s));
			exit(EXIT_FAILURE);
		}
		if (strcmp(host, target_host) != 0)
			continue;
		if_found = 1;

		snprintf(TARGET_ETH, sizeof(TARGET_ETH), "%s", ifa->ifa_name);
		break;
	}

	freeifaddrs(ifaddr);

	return if_found;
}

void execute(char* cmd) {
#ifndef SILENT_EXEC
	fprintf(stdout, "[-] Executing `%s`\n", cmd);
#endif
	int err = system(cmd);
	if (err) {die_with(cmd, err);}
}

void die_with(char* msg, int code) {
	perror(msg);
	exit(code);
}

void hook_sig(void) {
	struct sigaction sa;
	sa.sa_handler = &cleanup;
	sigfillset(&sa.sa_mask);

	if (sigaction(SIGHUP, &sa, NULL) || sigaction(SIGINT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL))
		die_with("Failed to process signal", EXIT_FAILURE);
}

void help_exit(char* p) {
	printf("Usage: %s [-c] [-p] [-h] SERVER_IP CIDR_NEW|CIDR_PIVOT\n", p);
	printf("\n");
	printf("          -h:  view this help message\n");
	printf("          -c:  run as client (requires CIDR_NEW)\n");
	printf("               (if not specified run as server (requires CIDR_PIVOT))\n");
	printf("          -p:  fake promiscuous mode (think of NAT but for MAC)\n");
	printf("               (only applies on server, see `Notes` for more details)\n");
	printf("   SERVER_IP:  the ip address of the interface on the server that will be used for the tunnel\n");
	printf("    CIDR_NEW:  the new ip address on the client (including the subnet mask in CIDR notation)\n");
	printf("               (the netmask must match the target network and you should choose an available IP address)\n");
	printf("  CIDR_PIVOT:  the ip address of the interface to pivot to (including the subnet mask in CIDR notation)\n");
	printf("\n");
	printf("Example:\n");
	printf(" (Client: 10.0.0.1)      (Server: 10.0.0.2 & 172.16.0.2)      (Target: 172.16.0.1)\n");
	printf("\n");
	printf("         Server# %s [-p] 10.0.0.2 172.16.0.2/24\n", p);
	printf("         Client# %s -c 10.0.0.2 172.16.0.3/24\n", p);
	printf("\n");
	printf(" ==> (Client: 10.0.0.1 & 172.16.0.3)\n");
	printf("\n");
	printf("Notes:\n");
	printf("  About `-p`. In virtual environments where the hypervisor disabled promiscuous mode for the server NIC\n");
	printf("  the server will not be able to process responses directed towards the client. In this case (and any\n");
	printf("  other scenario where the NIC cannot be placed in promiscuous mode) use `-p` to masque all MAC addresses.\n");
	printf("  Keep in mind that the target network will no longer be able to access services on this server anymore!\n");
	printf("\n");
	printf("  Be advised, proxying ARP may confuse some tools. Use `nmap` with `--disable-arp-ping`.\n");
	printf("\n");
	exit(EXIT_FAILURE);
}

void display_config(int is_client, char* tap_id) {
	printf("-------------------------------------------\n");
	printf("[CONFIG]\n");
	printf("    mode              : %s\n", (is_client?"CLIENT": "SERVER"));
	printf("    tap interface     : %s\n", tap_id);
	if (is_client) {
		printf("    tap mac address   : %s\n", SPOOF_MAC);
		printf("    tunneling via     : %s:%i\n", UDP_TARGET, UDP_PORT);
		printf("    tap ip address    : %.*s\n", (int) strcspn(TARGET_CIDR, "/"), TARGET_CIDR);
	} else {
		printf("    promiscuous mode  : %s\n", (PROMISCUOUS_ENABLED ? "enabled" : "disabled (faking it)*"));
		printf("    serving tunnel on : %s:%i\n", UDP_TARGET, UDP_PORT);
		printf("    target network    : %s (%s)\n", TARGET_CIDR, TARGET_ETH);
	}
	printf("-------------------------------------------\n");
	if (!is_client && !PROMISCUOUS_ENABLED)
		printf("*) be aware of what you're executing (e.g. `nmap` will require `--disable-arp-ping`)\n");
}
