package main

// Ciphers is a list of known ciphers
// Source: http://www.thesprawl.org/research/tls-and-ssl-cipher-suites/
var Ciphers = []Cipher{
	Cipher{"0x000000", "TLS_NULL_WITH_NULL_NULL", "TLS", "NULL", "NULL", "NULL", "0", "NULL"},
	Cipher{"0x000001", "TLS_RSA_WITH_NULL_MD5", "TLS", "RSA", "RSA", "NULL", "0", "MD5"},
	Cipher{"0x000002", "TLS_RSA_WITH_NULL_SHA", "TLS", "RSA", "RSA", "NULL", "0", "SHA"},
	Cipher{"0x000003", "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "TLS", "RSA_EXPORT", "RSA_EXPORT", "RC4_40", "40", "MD5"},
	Cipher{"0x000004", "TLS_RSA_WITH_RC4_128_MD5", "TLS", "RSA", "RSA", "RC4_128", "128", "MD5"},
	Cipher{"0x000005", "TLS_RSA_WITH_RC4_128_SHA", "TLS", "RSA", "RSA", "RC4_128", "128", "SHA"},
	Cipher{"0x000006", "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "TLS", "RSA_EXPORT", "RSA_EXPORT", "RC2_CBC_40", "40", "MD5"},
	Cipher{"0x000007", "TLS_RSA_WITH_IDEA_CBC_SHA", "TLS", "RSA", "RSA", "IDEA_CBC", "128", "SHA"},
	Cipher{"0x000008", "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS", "RSA_EXPORT", "RSA_EXPORT", "DES40_CBC", "40", "SHA"},
	Cipher{"0x000009", "TLS_RSA_WITH_DES_CBC_SHA", "TLS", "RSA", "RSA", "DES_CBC", "56", "SHA"},
	Cipher{"0x00000A", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS", "RSA", "RSA", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00000B", "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", "TLS", "DH", "DSS", "DES40_CBC", "40", "SHA"},
	Cipher{"0x00000C", "TLS_DH_DSS_WITH_DES_CBC_SHA", "TLS", "DH", "DSS", "DES_CBC", "56", "SHA"},
	Cipher{"0x00000D", "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", "TLS", "DH", "DSS", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00000E", "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS", "DH", "RSA", "DES40_CBC", "40", "SHA"},
	Cipher{"0x00000F", "TLS_DH_RSA_WITH_DES_CBC_SHA", "TLS", "DH", "RSA", "DES_CBC", "56", "SHA"},
	Cipher{"0x000010", "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", "TLS", "DH", "RSA", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x000011", "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "TLS", "DHE", "DSS", "DES40_CBC", "40", "SHA"},
	Cipher{"0x000012", "TLS_DHE_DSS_WITH_DES_CBC_SHA", "TLS", "DHE", "DSS", "DES_CBC", "56", "SHA"},
	Cipher{"0x000013", "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "TLS", "DHE", "DSS", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x000014", "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS", "DHE", "RSA", "DES40_CBC", "40", "SHA"},
	Cipher{"0x000015", "TLS_DHE_RSA_WITH_DES_CBC_SHA", "TLS", "DHE", "RSA", "DES_CBC", "56", "SHA"},
	Cipher{"0x000016", "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "TLS", "DHE", "RSA", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x000017", "TLS_DH_Anon_EXPORT_WITH_RC4_40_MD5", "TLS", "DH", "Anon", "RC4_40", "40", "MD5"},
	Cipher{"0x000018", "TLS_DH_Anon_WITH_RC4_128_MD5", "TLS", "DH", "Anon", "RC4_128", "128", "MD5"},
	Cipher{"0x000019", "TLS_DH_Anon_EXPORT_WITH_DES40_CBC_SHA", "TLS", "DH", "Anon", "DES40_CBC", "40", "SHA"},
	Cipher{"0x00001A", "TLS_DH_Anon_WITH_DES_CBC_SHA", "TLS", "DH", "Anon", "DES_CBC", "56", "SHA"},
	Cipher{"0x00001B", "TLS_DH_Anon_WITH_3DES_EDE_CBC_SHA", "TLS", "DH", "Anon", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00001C", "SSL_FORTEZZA_KEA_WITH_NULL_SHA", "SSL", "FORTEZZA", "KEA", "NULL", "0", "SHA"},
	Cipher{"0x00001D", "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA", "SSL", "FORTEZZA", "KEA", "FORTEZZA_CBC", "80", "SHA"},
	Cipher{"0x00001E", "TLS_KRB5_WITH_DES_CBC_SHA", "TLS", "KRB5", "KRB5", "DES_CBC", "56", "SHA"},
	Cipher{"0x00001F", "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", "TLS", "KRB5", "KRB5", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x000020", "TLS_KRB5_WITH_RC4_128_SHA", "TLS", "KRB5", "KRB5", "RC4_128", "128", "SHA"},
	Cipher{"0x000021", "TLS_KRB5_WITH_IDEA_CBC_SHA", "TLS", "KRB5", "KRB5", "IDEA_CBC", "128", "SHA"},
	Cipher{"0x000022", "TLS_KRB5_WITH_DES_CBC_MD5", "TLS", "KRB5", "KRB5", "DES_CBC", "56", "MD5"},
	Cipher{"0x000023", "TLS_KRB5_WITH_3DES_EDE_CBC_MD5", "TLS", "KRB5", "KRB5", "3DES_EDE_CBC", "168", "MD5"},
	Cipher{"0x000024", "TLS_KRB5_WITH_RC4_128_MD5", "TLS", "KRB5", "KRB5", "RC4_128", "128", "MD5"},
	Cipher{"0x000025", "TLS_KRB5_WITH_IDEA_CBC_MD5", "TLS", "KRB5", "KRB5", "IDEA_CBC", "128", "MD5"},
	Cipher{"0x000026", "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", "TLS", "KRB5_EXPORT", "KRB5_EXPORT", "DES_CBC_40", "40", "SHA"},
	Cipher{"0x000027", "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", "TLS", "KRB5_EXPORT", "KRB5_EXPORT", "RC2_CBC_40", "40", "SHA"},
	Cipher{"0x000028", "TLS_KRB5_EXPORT_WITH_RC4_40_SHA", "TLS", "KRB5_EXPORT", "KRB5_EXPORT", "RC4_40", "40", "SHA"},
	Cipher{"0x000029", "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", "TLS", "KRB5_EXPORT", "KRB5_EXPORT", "DES_CBC_40", "40", "MD5"},
	Cipher{"0x00002A", "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", "TLS", "KRB5_EXPORT", "KRB5_EXPORT", "RC2_CBC_40", "40", "MD5"},
	Cipher{"0x00002B", "TLS_KRB5_EXPORT_WITH_RC4_40_MD5", "TLS", "KRB5_EXPORT", "KRB5_EXPORT", "RC4_40", "40", "MD5"},
	Cipher{"0x00002C", "TLS_PSK_WITH_NULL_SHA", "TLS", "PSK", "PSK", "NULL", "0", "SHA"},
	Cipher{"0x00002D", "TLS_DHE_PSK_WITH_NULL_SHA", "TLS", "DHE", "PSK", "NULL", "0", "SHA"},
	Cipher{"0x00002E", "TLS_RSA_PSK_WITH_NULL_SHA", "TLS", "RSA", "PSK", "NULL", "0", "SHA"},
	Cipher{"0x00002F", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS", "RSA", "RSA", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x000030", "TLS_DH_DSS_WITH_AES_128_CBC_SHA", "TLS", "DH", "DSS", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x000031", "TLS_DH_RSA_WITH_AES_128_CBC_SHA", "TLS", "DH", "RSA", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x000032", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "TLS", "DHE", "DSS", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x000033", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS", "DHE", "RSA", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x000034", "TLS_DH_Anon_WITH_AES_128_CBC_SHA", "TLS", "DH", "Anon", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x000035", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS", "RSA", "RSA", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x000036", "TLS_DH_DSS_WITH_AES_256_CBC_SHA", "TLS", "DH", "DSS", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x000037", "TLS_DH_RSA_WITH_AES_256_CBC_SHA", "TLS", "DH", "RSA", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x000038", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "TLS", "DHE", "DSS", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x000039", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "TLS", "DHE", "RSA", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x00003A", "TLS_DH_Anon_WITH_AES_256_CBC_SHA", "TLS", "DH", "Anon", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x00003B", "TLS_RSA_WITH_NULL_SHA256", "TLS", "RSA", "RSA", "NULL", "0", "SHA256"},
	Cipher{"0x00003C", "TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS", "RSA", "RSA", "AES_128_CBC", "128", "SHA256"},
	Cipher{"0x00003D", "TLS_RSA_WITH_AES_256_CBC_SHA256", "TLS", "RSA", "RSA", "AES_256_CBC", "256", "SHA256"},
	Cipher{"0x00003E", "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", "TLS", "DH", "DSS", "AES_128_CBC", "128", "SHA256"},
	Cipher{"0x00003F", "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", "TLS", "DH", "RSA", "AES_128_CBC", "128", "SHA256"},
	Cipher{"0x000040", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "TLS", "DHE", "DSS", "AES_128_CBC", "128", "SHA256"},
	Cipher{"0x000041", "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS", "RSA", "RSA", "CAMELLIA_128_CBC", "128", "SHA"},
	Cipher{"0x000042", "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", "TLS", "DH", "DSS", "CAMELLIA_128_CBC", "128", "SHA"},
	Cipher{"0x000043", "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS", "DH", "RSA", "CAMELLIA_128_CBC", "128", "SHA"},
	Cipher{"0x000044", "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", "TLS", "DHE", "DSS", "CAMELLIA_128_CBC", "128", "SHA"},
	Cipher{"0x000045", "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS", "DHE", "RSA", "CAMELLIA_128_CBC", "128", "SHA"},
	Cipher{"0x000046", "TLS_DH_Anon_WITH_CAMELLIA_128_CBC_SHA", "TLS", "DH", "Anon", "CAMELLIA_128_CBC", "128", "SHA"},
	Cipher{"0x000047", "TLS_ECDH_ECDSA_WITH_NULL_SHA", "TLS", "ECDH", "ECDSA", "NULL", "0", "SHA"},
	Cipher{"0x000048", "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "TLS", "ECDH", "ECDSA", "RC4_128", "128", "SHA"},
	Cipher{"0x000049", "TLS_ECDH_ECDSA_WITH_DES_CBC_SHA", "TLS", "ECDH", "ECDSA", "DES_CBC", "56", "SHA"},
	Cipher{"0x00004A", "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "TLS", "ECDH", "ECDSA", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00004B", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", "TLS", "ECDH", "ECDSA", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x00004C", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", "TLS", "ECDH", "ECDSA", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x000060", "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5", "TLS", "RSA_EXPORT 1024", "RSA_EXPORT 1024", "RC4_56", "56", "MD5"},
	Cipher{"0x000061", "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5", "TLS", "RSA_EXPORT 1024", "RSA_EXPORT 1024", "RC2_CBC_56", "56", "MD5"},
	Cipher{"0x000062", "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", "TLS", "RSA_EXPORT 1024", "RSA_EXPORT 1024", "DES_CBC", "56", "SHA"},
	Cipher{"0x000063", "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA", "TLS", "DHE", "DSS", "DES_CBC", "56", "SHA"},
	Cipher{"0x000064", "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", "TLS", "RSA_EXPORT 1024", "RSA_EXPORT 1024", "RC4_56", "56", "SHA"},
	Cipher{"0x000065", "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA", "TLS", "DHE", "DSS", "RC4_56", "56", "SHA"},
	Cipher{"0x000066", "TLS_DHE_DSS_WITH_RC4_128_SHA", "TLS", "DHE", "DSS", "RC4_128", "128", "SHA"},
	Cipher{"0x000067", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "TLS", "DHE", "RSA", "AES_128_CBC", "128", "SHA256"},
	Cipher{"0x000068", "TLS_DH_DSS_WITH_AES_256_CBC_SHA256", "TLS", "DH", "DSS", "AES_256_CBC", "256", "SHA256"},
	Cipher{"0x000069", "TLS_DH_RSA_WITH_AES_256_CBC_SHA256", "TLS", "DH", "RSA", "AES_256_CBC", "256", "SHA256"},
	Cipher{"0x00006A", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "TLS", "DHE", "DSS", "AES_256_CBC", "256", "SHA256"},
	Cipher{"0x00006B", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "TLS", "DHE", "RSA", "AES_256_CBC", "256", "SHA256"},
	Cipher{"0x00006C", "TLS_DH_Anon_WITH_AES_128_CBC_SHA256", "TLS", "DH", "Anon", "AES_128_CBC", "128", "SHA256"},
	Cipher{"0x00006D", "TLS_DH_Anon_WITH_AES_256_CBC_SHA256", "TLS", "DH", "Anon", "AES_256_CBC", "256", "SHA256"},
	Cipher{"0x000080", "TLS_GOSTR341094_WITH_28147_CNT_IMIT", "TLS", "VKO GOST R 34.10-94", "VKO GOST R 34.10-94", "GOST28147", "256", "GOST28147"},
	Cipher{"0x000081", "TLS_GOSTR341001_WITH_28147_CNT_IMIT", "TLS", "VKO GOST R 34.10-2001", "VKO GOST R 34.10-2001", "GOST28147", "256", "GOST28147"},
	Cipher{"0x000082", "TLS_GOSTR341094_WITH_NULL_GOSTR3411", "TLS", "VKO GOST R 34.10-94", "VKO GOST R 34.10-94", "NULL", "0", "GOSTR3411"},
	Cipher{"0x000083", "TLS_GOSTR341001_WITH_NULL_GOSTR3411", "TLS", "VKO GOST R 34.10-2001", "VKO GOST R 34.10-2001", "NULL", "0", "GOSTR3411"},
	Cipher{"0x000084", "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS", "RSA", "RSA", "CAMELLIA_256_CBC", "256", "SHA"},
	Cipher{"0x000085", "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", "TLS", "DH", "DSS", "CAMELLIA_256_CBC", "256", "SHA"},
	Cipher{"0x000086", "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS", "DH", "RSA", "CAMELLIA_256_CBC", "256", "SHA"},
	Cipher{"0x000087", "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", "TLS", "DHE", "DSS", "CAMELLIA_256_CBC", "256", "SHA"},
	Cipher{"0x000088", "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", "TLS", "DHE", "RSA", "CAMELLIA_256_CBC", "256", "SHA"},
	Cipher{"0x000089", "TLS_DH_Anon_WITH_CAMELLIA_256_CBC_SHA", "TLS", "DH", "Anon", "CAMELLIA_256_CBC", "256", "SHA"},
	Cipher{"0x00008A", "TLS_PSK_WITH_RC4_128_SHA", "TLS", "PSK", "PSK", "RC4_128", "128", "SHA"},
	Cipher{"0x00008B", "TLS_PSK_WITH_3DES_EDE_CBC_SHA", "TLS", "PSK", "PSK", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00008C", "TLS_PSK_WITH_AES_128_CBC_SHA", "TLS", "PSK", "PSK", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x00008D", "TLS_PSK_WITH_AES_256_CBC_SHA", "TLS", "PSK", "PSK", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x00008E", "TLS_DHE_PSK_WITH_RC4_128_SHA", "TLS", "DHE", "PSK", "RC4_128", "128", "SHA"},
	Cipher{"0x00008F", "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", "TLS", "DHE", "PSK", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x000090", "TLS_DHE_PSK_WITH_AES_128_CBC_SHA", "TLS", "DHE", "PSK", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x000091", "TLS_DHE_PSK_WITH_AES_256_CBC_SHA", "TLS", "DHE", "PSK", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x000092", "TLS_RSA_PSK_WITH_RC4_128_SHA", "TLS", "RSA", "PSK", "RC4_128", "128", "SHA"},
	Cipher{"0x000093", "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", "TLS", "RSA", "PSK", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x000094", "TLS_RSA_PSK_WITH_AES_128_CBC_SHA", "TLS", "RSA", "PSK", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x000095", "TLS_RSA_PSK_WITH_AES_256_CBC_SHA", "TLS", "RSA", "PSK", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x000096", "TLS_RSA_WITH_SEED_CBC_SHA", "TLS", "RSA", "RSA", "SEED_CBC", "128", "SHA"},
	Cipher{"0x000097", "TLS_DH_DSS_WITH_SEED_CBC_SHA", "TLS", "DH", "DSS", "SEED_CBC", "128", "SHA"},
	Cipher{"0x000098", "TLS_DH_RSA_WITH_SEED_CBC_SHA", "TLS", "DH", "RSA", "SEED_CBC", "128", "SHA"},
	Cipher{"0x000099", "TLS_DHE_DSS_WITH_SEED_CBC_SHA", "TLS", "DHE", "DSS", "SEED_CBC", "128", "SHA"},
	Cipher{"0x00009A", "TLS_DHE_RSA_WITH_SEED_CBC_SHA", "TLS", "DHE", "RSA", "SEED_CBC", "128", "SHA"},
	Cipher{"0x00009B", "TLS_DH_Anon_WITH_SEED_CBC_SHA", "TLS", "DH", "Anon", "SEED_CBC", "128", "SHA"},
	Cipher{"0x00009C", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS", "RSA", "RSA", "AES_128_GCM", "128", "SHA256"},
	Cipher{"0x00009D", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS", "RSA", "RSA", "AES_256_GCM", "256", "SHA384"},
	Cipher{"0x00009E", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS", "DHE", "RSA", "AES_128_GCM", "128", "SHA256"},
	Cipher{"0x00009F", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "TLS", "DHE", "RSA", "AES_256_GCM", "256", "SHA384"},
	Cipher{"0x0000A0", "TLS_DH_RSA_WITH_AES_128_GCM_SHA256", "TLS", "DH", "RSA", "AES_128_GCM", "128", "SHA256"},
	Cipher{"0x0000A1", "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", "TLS", "DH", "RSA", "AES_256_GCM", "256", "SHA384"},
	Cipher{"0x0000A2", "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "TLS", "DHE", "DSS", "AES_128_GCM", "128", "SHA256"},
	Cipher{"0x0000A3", "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", "TLS", "DHE", "DSS", "AES_256_GCM", "256", "SHA384"},
	Cipher{"0x0000A4", "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", "TLS", "DH", "DSS", "AES_128_GCM", "128", "SHA256"},
	Cipher{"0x0000A5", "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", "TLS", "DH", "DSS", "AES_256_GCM", "256", "SHA384"},
	Cipher{"0x0000A6", "TLS_DH_Anon_WITH_AES_128_GCM_SHA256", "TLS", "DH", "Anon", "AES_128_GCM", "128", "SHA256"},
	Cipher{"0x0000A7", "TLS_DH_Anon_WITH_AES_256_GCM_SHA384", "TLS", "DH", "Anon", "AES_256_GCM", "256", "SHA384"},
	Cipher{"0x0000A8", "TLS_PSK_WITH_AES_128_GCM_SHA256", "TLS", "PSK", "PSK", "AES_128_GCM", "128", "SHA256"},
	Cipher{"0x0000A9", "TLS_PSK_WITH_AES_256_GCM_SHA384", "TLS", "PSK", "PSK", "AES_256_GCM", "256", "SHA384"},
	Cipher{"0x0000AA", "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", "TLS", "DHE", "PSK", "AES_128_GCM", "128", "SHA256"},
	Cipher{"0x0000AB", "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", "TLS", "DHE", "PSK", "AES_256_GCM", "256", "SHA384"},
	Cipher{"0x0000AC", "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", "TLS", "RSA", "PSK", "AES_128_GCM", "128", "SHA256"},
	Cipher{"0x0000AD", "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", "TLS", "RSA", "PSK", "AES_256_GCM", "256", "SHA384"},
	Cipher{"0x0000AE", "TLS_PSK_WITH_AES_128_CBC_SHA256", "TLS", "PSK", "PSK", "AES_128_CBC", "128", "SHA256"},
	Cipher{"0x0000AF", "TLS_PSK_WITH_AES_256_CBC_SHA384", "TLS", "PSK", "PSK", "AES_256_CBC", "256", "SHA384"},
	Cipher{"0x0000B0", "TLS_PSK_WITH_NULL_SHA256", "TLS", "PSK", "PSK", "NULL", "0", "SHA256"},
	Cipher{"0x0000B1", "TLS_PSK_WITH_NULL_SHA384", "TLS", "PSK", "PSK", "NULL", "0", "SHA384"},
	Cipher{"0x0000B2", "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", "TLS", "DHE", "PSK", "AES_128_CBC", "128", "SHA256"},
	Cipher{"0x0000B3", "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", "TLS", "DHE", "PSK", "AES_256_CBC", "256", "SHA384"},
	Cipher{"0x0000B4", "TLS_DHE_PSK_WITH_NULL_SHA256", "TLS", "DHE", "PSK", "NULL", "0", "SHA256"},
	Cipher{"0x0000B5", "TLS_DHE_PSK_WITH_NULL_SHA384", "TLS", "DHE", "PSK", "NULL", "0", "SHA384"},
	Cipher{"0x0000B6", "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256", "TLS", "RSA", "PSK", "AES_128_CBC", "128", "SHA256"},
	Cipher{"0x0000B7", "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384", "TLS", "RSA", "PSK", "AES_256_CBC", "256", "SHA384"},
	Cipher{"0x0000B8", "TLS_RSA_PSK_WITH_NULL_SHA256", "TLS", "RSA", "PSK", "NULL", "0", "SHA256"},
	Cipher{"0x0000B9", "TLS_RSA_PSK_WITH_NULL_SHA384", "TLS", "RSA", "PSK", "NULL", "0", "SHA384"},
	Cipher{"0x00C001", "TLS_ECDH_ECDSA_WITH_NULL_SHA", "TLS", "ECDH", "ECDSA", "NULL", "0", "SHA"},
	Cipher{"0x00C002", "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "TLS", "ECDH", "ECDSA", "RC4_128", "128", "SHA"},
	Cipher{"0x00C003", "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "TLS", "ECDH", "ECDSA", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00C004", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", "TLS", "ECDH", "ECDSA", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x00C005", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", "TLS", "ECDH", "ECDSA", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x00C006", "TLS_ECDHE_ECDSA_WITH_NULL_SHA", "TLS", "ECDHE", "ECDSA", "NULL", "0", "SHA"},
	Cipher{"0x00C007", "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "TLS", "ECDHE", "ECDSA", "RC4_128", "128", "SHA"},
	Cipher{"0x00C008", "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "TLS", "ECDHE", "ECDSA", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00C009", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS", "ECDHE", "ECDSA", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x00C00A", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLS", "ECDHE", "ECDSA", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x00C00B", "TLS_ECDH_RSA_WITH_NULL_SHA", "TLS", "ECDH", "RSA", "NULL", "0", "SHA"},
	Cipher{"0x00C00C", "TLS_ECDH_RSA_WITH_RC4_128_SHA", "TLS", "ECDH", "RSA", "RC4_128", "128", "SHA"},
	Cipher{"0x00C00D", "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", "TLS", "ECDH", "RSA", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00C00E", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "TLS", "ECDH", "RSA", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x00C00F", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", "TLS", "ECDH", "RSA", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x00C010", "TLS_ECDHE_RSA_WITH_NULL_SHA", "TLS", "ECDHE", "RSA", "NULL", "0", "SHA"},
	Cipher{"0x00C011", "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "TLS", "ECDHE", "RSA", "RC4_128", "128", "SHA"},
	Cipher{"0x00C012", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "TLS", "ECDHE", "RSA", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00C013", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS", "ECDHE", "RSA", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x00C014", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS", "ECDHE", "RSA", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x00C015", "TLS_ECDH_Anon_WITH_NULL_SHA", "TLS", "ECDH", "Anon", "NULL", "0", "SHA"},
	Cipher{"0x00C016", "TLS_ECDH_Anon_WITH_RC4_128_SHA", "TLS", "ECDH", "Anon", "RC4_128", "128", "SHA"},
	Cipher{"0x00C017", "TLS_ECDH_Anon_WITH_3DES_EDE_CBC_SHA", "TLS", "ECDH", "Anon", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00C018", "TLS_ECDH_Anon_WITH_AES_128_CBC_SHA", "TLS", "ECDH", "Anon", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x00C019", "TLS_ECDH_Anon_WITH_AES_256_CBC_SHA", "TLS", "ECDH", "Anon", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x00C01A", "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", "TLS", "SRP", "SHA", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00C01B", "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", "TLS", "SRP", "SHA", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00C01C", "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", "TLS", "SRP", "SHA", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00C01D", "TLS_SRP_SHA_WITH_AES_128_CBC_SHA", "TLS", "SRP", "SHA", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x00C01E", "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", "TLS", "SRP", "SHA", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x00C01F", "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", "TLS", "SRP", "SHA", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x00C020", "TLS_SRP_SHA_WITH_AES_256_CBC_SHA", "TLS", "SRP", "SHA", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x00C021", "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", "TLS", "SRP", "SHA", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x00C022", "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", "TLS", "SRP", "SHA", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x00C023", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS", "ECDHE", "ECDSA", "AES_128_CBC", "128", "SHA256"},
	Cipher{"0x00C024", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS", "ECDHE", "ECDSA", "AES_256_CBC", "256", "SHA384"},
	Cipher{"0x00C025", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "TLS", "ECDH", "ECDSA", "AES_128_CBC", "128", "SHA256"},
	Cipher{"0x00C026", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", "TLS", "ECDH", "ECDSA", "AES_256_CBC", "256", "SHA384"},
	Cipher{"0x00C027", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS", "ECDHE", "RSA", "AES_128_CBC", "128", "SHA256"},
	Cipher{"0x00C028", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "TLS", "ECDHE", "RSA", "AES_256_CBC", "256", "SHA384"},
	Cipher{"0x00C029", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "TLS", "ECDH", "RSA", "AES_128_CBC", "128", "SHA256"},
	Cipher{"0x00C02A", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", "TLS", "ECDH", "RSA", "AES_256_CBC", "256", "SHA384"},
	Cipher{"0x00C02B", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS", "ECDHE", "ECDSA", "AES_128_GCM", "128", "SHA256"},
	Cipher{"0x00C02C", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS", "ECDHE", "ECDSA", "AES_256_GCM", "256", "SHA384"},
	Cipher{"0x00C02D", "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "TLS", "ECDH", "ECDSA", "AES_128_GCM", "128", "SHA256"},
	Cipher{"0x00C02E", "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "TLS", "ECDH", "ECDSA", "AES_256_GCM", "256", "SHA384"},
	Cipher{"0x00C02F", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS", "ECDHE", "RSA", "AES_128_GCM", "128", "SHA256"},
	Cipher{"0x00C030", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS", "ECDHE", "RSA", "AES_256_GCM", "256", "SHA384"},
	Cipher{"0x00C031", "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "TLS", "ECDH", "RSA", "AES_128_GCM", "128", "SHA256"},
	Cipher{"0x00C032", "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "TLS", "ECDH", "RSA", "AES_256_GCM", "256", "SHA384"},
	Cipher{"0x00C033", "TLS_ECDHE_PSK_WITH_RC4_128_SHA", "TLS", "ECDHE", "PSK", "RC4_128", "128", "SHA"},
	Cipher{"0x00C034", "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", "TLS", "ECDHE", "PSK", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00C035", "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", "TLS", "ECDHE", "PSK", "AES_128_CBC", "128", "SHA"},
	Cipher{"0x00C036", "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", "TLS", "ECDHE", "PSK", "AES_256_CBC", "256", "SHA"},
	Cipher{"0x00C037", "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", "TLS", "ECDHE", "PSK", "AES_128_CBC", "128", "SHA256"},
	Cipher{"0x00C038", "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", "TLS", "ECDHE", "PSK", "AES_256_CBC", "256", "SHA384"},
	Cipher{"0x00C039", "TLS_ECDHE_PSK_WITH_NULL_SHA", "TLS", "ECDHE", "PSK", "NULL", "0", "SHA"},
	Cipher{"0x00C03A", "TLS_ECDHE_PSK_WITH_NULL_SHA256", "TLS", "ECDHE", "PSK", "NULL", "0", "SHA256"},
	Cipher{"0x00C03B", "TLS_ECDHE_PSK_WITH_NULL_SHA384", "TLS", "ECDHE", "PSK", "NULL", "0", "SHA384"},
	Cipher{"0x00FEFE", "SSL_RSA_FIPS_WITH_DES_CBC_SHA", "SSL", "RSA_FIPS", "RSA_FIPS", "DES_CBC", "56", "SHA"},
	Cipher{"0x00FEFF", "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", "SSL", "RSA_FIPS", "RSA_FIPS", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00FFE0", "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", "SSL", "RSA_FIPS", "RSA_FIPS", "3DES_EDE_CBC", "168", "SHA"},
	Cipher{"0x00FFE1", "SSL_RSA_FIPS_WITH_DES_CBC_SHA", "SSL", "RSA_FIPS", "RSA_FIPS", "DES_CBC", "56", "SHA"},
	Cipher{"0x010080", "SSL2_RC4_128_WITH_MD5", "SSL2", "RSA", "RSA", "RC4_128", "128", "MD5"},
	Cipher{"0x020080", "SSL2_RC4_128_EXPORT40_WITH_MD5", "SSL2", "RSA", "RSA", "RC4_128_EXPORT40", "40", "MD5"},
	Cipher{"0x030080", "SSL2_RC2_CBC_128_CBC_WITH_MD5", "SSL2", "RSA", "RSA", "RC2_CBC_128_CBC", "128", "MD5"},
	Cipher{"0x040080", "SSL2_RC2_CBC_128_CBC_WITH_MD5", "SSL2", "RSA", "RSA", "RC2_CBC_128_CBC", "128", "MD5"},
	Cipher{"0x050080", "SSL2_IDEA_128_CBC_WITH_MD5", "SSL2", "RSA", "RSA", "IDEA_128_CBC", "128", "MD5"},
	Cipher{"0x060040", "SSL2_DES_64_CBC_WITH_MD5", "SSL2", "RSA", "RSA", "DES_64_CBC", "64", "MD5"},
	Cipher{"0x0700C0", "SSL2_DES_192_EDE3_CBC_WITH_MD5", "SSL2", "RSA", "RSA", "DES_192_EDE3_CBC", "192", "MD5"},
	Cipher{"0x080080", "SSL2_RC4_64_WITH_MD5", "SSL2", "RSA", "RSA", "RC4_64", "64", "MD5"},
	Cipher{"0x800001", "PCT_SSL_CERT_TYPE", "PCT1_CERT_X509", "PCT", "", "", "", ""},
	Cipher{"0x800003", "PCT_SSL_CERT_TYPE", "PCT1_CERT_X509_CHAIN", "PCT", "", "", "", ""},
	Cipher{"0x810001", "PCT_SSL_HASH_TYPE", "PCT1_HASH_MD5", "PCT", "", "", "", ""},
	Cipher{"0x810003", "PCT_SSL_HASH_TYPE", "PCT1_HASH_SHA", "PCT", "", "", "", ""},
	Cipher{"0x820001", "PCT_SSL_EXCH_TYPE", "PCT1_EXCH_RSA_PKCS1", "PCT", "", "", "", ""},
	Cipher{"0x830004", "PCT_SSL_CIPHER_TYPE_1ST_HALF", "PCT1_CIPHER_RC4", "PCT", "", "", "", ""},
	Cipher{"0x842840", "PCT_SSL_CIPHER_TYPE_2ND_HALF", "PCT1_ENC_BITS_40", "PCT1_MAC_BITS 128", "PCT", "", "", ""},
	Cipher{"0x848040", "PCT_SSL_CIPHER_TYPE_2ND_HALF", "PCT1_ENC_BITS_128", "PCT1_MAC_BITS 128", "PCT", "", "", ""},
	Cipher{"0x8F8001", "PCT_SSL_COMPAT", "PCT_VERSION_1", "PCT", "", "", "", ""},
	// Added by me
	Cipher{"0x0000FF", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "", "", "", "", "", ""},
}