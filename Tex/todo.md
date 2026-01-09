EDIT:   1. Add more shor and qkd (quantum approach), Reduce SIMD.
DONE:   1.3.,
DONE:   2.1, 
DONE:   2.2
EXPAND: 2.4.5. Biraz daha detaylı anlatılabilir
EDIT:   3.1.1 sub For C implementation, express performance meausurability.
DELETE: 3.2
ADD:     3.2 ECC, detaylandırılmalı
ADD:     3.3 KYBER, ntt, shake128, centered binomial dist gibi konular buranın alt başlığı olmalı
EDIT:    3.4 Belki simd yanında, multithreadeddan bahsedilebilir, kyber emberrassingly parallel.
EDIT:    3.6, kod satırlarına gerek yok, (daha generic olabilir mi bilemedim?), lib.py lib.cnin lib olduğuna dikkat çekmek mantıklı, lib.py içerisinde testler de var.
EDIT:    4.2.1, Simd olmayan halleri tabloya eklenebilir (eklenirse yazının da değişmesi lazım), yüzdeler verilen sayılar vs kontrol edilmeli

EDIT:   4.5. bu başlık kendi başına önemli ama yanlış ele alınmış. Kyber kullanılmaya başlanacağı zaman ne gibi değişiklikler ve düzenlemeler beklenmeli, aşamaları gibi şeylerden bahsedilmeli daha çok
EDIT:   4.5.1, başlık değişebilir
EDIT:   4.5.2 bu kısım çok ai geldi, biraz daha teknik kalabilir (direkt silinebilir)
EDIT:   4.5.3 kyber implementation guide a dönmüş biraz, bu başlık kalabilir ama daha tarafsız(?) bir dille anlatılmalı, burada daha çok araştırma gerekiyora kayabiliriz.
EDIT:   4.5.4. Rewordle, çalışmada çok fazla çalıştırıp ortalama aldığımızı belirtmiş olalım, stabiliteye dikkat çekilir.
EDIT:   5.1. Çok satmışız, sade to the point dümdüz ilerlemek lazım.
EDIT:   5.3. lattice VE LWE muhabbeti, lwe eklenmeli. C için Kyber paramları vs, biraz sıkıntı çıkardı, serverı maintain etmek sıkıntılıydı.
EDIT:   5.4.2. ARM NEON Yerine Edge Computation Devices
CREATE: 5.4.4 Middleware based, web plugin?, over-tls-layer

EDIT: Bibliography, shit ton of referance lazim, ungodly amounts of referance, ve raporda nerelerde kullaniliyorsa bahsedilmeli, 

GENEL EDIT: Bahsedilen bilgilerin referanslarına göre belirtilmeleri lazım kullanılan yerlerde (e.g. Kyber anlatılan yerde nist in kyber spesifikasyonu)

GENEL EDIT2: Wording, diğer editler yapılırken göze çarpan kısımlar törpülensin, ayrıca sonda baştan sona okunup wording düzenlemesi yapılacak.
