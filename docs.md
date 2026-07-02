# Prompt dla GitHub Copilot Chat — Web Security Scanner

Skopiuj poniższy tekst i wklej jako pierwszą wiadomość w Copilot Chat (agent mode / workspace mode).
Jeśli chcesz, żeby Copilot trzymał się tego przez cały czas pracy nad projektem, zapisz go też jako
`.github/copilot-instructions.md` w repo — Copilot będzie go automatycznie doczytywał w każdej sesji.

---

## PROMPT (skopiuj od tej linii)

Buduję aplikację "WebSec Scanner" — orkiestrator do audytu bezpieczeństwa stron internetowych,
wykonujący setki atomowych, pasywnych testów (pass/fail/warning/info) na wskazanej domenie,
za którą użytkownik ma zgodę na testowanie. To NIE jest narzędzie do ataku ani exploitacji —
wyłącznie wykrywanie i raportowanie błędnej konfiguracji, przestarzałych wersji, brakujących
zabezpieczeń itd. Zero payloadów ofensywnych, zero prób włamania.

### Stack techniczny
- Backend: Python 3.12, FastAPI
- Kolejka zadań: Celery + Redis (asynchroniczne skanowanie, długi czas wykonania)
- Baza danych: PostgreSQL (SQLAlchemy + Alembic do migracji)
- Frontend: Next.js 15 + TypeScript, SSE do streamowania wyników na żywo
- Raporty: generowanie PDF/HTML z podziałem na severity (Critical/High/Medium/Low/Info)
- Zewnętrzne narzędzia wywoływane jako subprocess: nmap, testssl.sh, nikto, whatweb
  (opcjonalnie OWASP ZAP przez jego REST API)
- Docker + docker-compose do uruchomienia całości lokalnie

### Architektura testów — WAŻNE
Każdy pojedynczy test to osobny moduł Python implementujący wspólny interfejs:

```python
class SecurityTest(ABC):
    id: str              # np. "headers.csp.unsafe_inline"
    category: str        # np. "HTTP Security Headers"
    severity: str         # "critical" | "high" | "medium" | "low" | "info"

    async def run(self, target: ScanContext) -> TestResult:
        ...
```

`TestResult` zawiera: status (pass/fail/warning/error), evidence (surowe dane potwierdzające wynik),
recommendation (jak naprawić), references (linki do OWASP/CWE).

Testy są rejestrowane w registry i odpalane równolegle (asyncio.gather z limitem concurrency),
pogrupowane w kategorie. Silnik skanujący nie wie nic o konkretnej logice testu — tylko iteruje
po registry i zbiera wyniki.

### Kategorie testów do zaimplementowania (buduj moduł po module, w tej kolejności)

Poniżej DOSŁOWNA lista każdego pojedynczego testu, jaki ma zostać zaimplementowany jako osobny
moduł/funkcja. Nie skracaj, nie generalizuj — każda pozycja to osobny plik/funkcja testowa
z własnym `id`.

**1. HTTP Security Headers**
1. CSP nagłówek obecny
2. CSP zawiera `unsafe-inline`
3. CSP zawiera `unsafe-eval`
4. CSP ma zdefiniowane `default-src`
5. CSP ma zdefiniowane `script-src`
6. CSP ma zdefiniowane `style-src`
7. CSP ma zdefiniowane `img-src`
8. CSP ma zdefiniowane `connect-src`
9. CSP ma zdefiniowane `object-src` (powinno być `none`)
10. CSP ma zdefiniowane `frame-ancestors`
11. CSP ma zdefiniowane `base-uri`
12. CSP ma zdefiniowane `form-action`
13. CSP zawiera `upgrade-insecure-requests`
14. CSP zawiera `block-all-mixed-content`
15. CSP ma `report-uri` lub `report-to`
16. HSTS nagłówek obecny
17. HSTS `max-age` ≥ 31536000 (rok)
18. HSTS zawiera `includeSubDomains`
19. HSTS zawiera `preload`
20. X-Frame-Options obecny i ma wartość DENY lub SAMEORIGIN
21. X-Content-Type-Options obecny i ma wartość `nosniff`
22. Referrer-Policy obecny
23. Referrer-Policy nie ma wartości `unsafe-url`
24. Permissions-Policy obecny
25. Permissions-Policy ogranicza `camera`
26. Permissions-Policy ogranicza `microphone`
27. Permissions-Policy ogranicza `geolocation`
28. Permissions-Policy ogranicza `payment`
29. Permissions-Policy ogranicza `usb`
30. Permissions-Policy ogranicza `fullscreen`
31. Permissions-Policy ogranicza `autoplay`
32. Permissions-Policy ogranicza `accelerometer`
33. Cross-Origin-Opener-Policy obecny
34. Cross-Origin-Embedder-Policy obecny
35. Cross-Origin-Resource-Policy obecny
36. Server header nie ujawnia wersji oprogramowania
37. X-Powered-By nie jest obecny
38. X-AspNet-Version nie jest obecny
39. X-AspNetMvc-Version nie jest obecny
40. Cache-Control ustawiony poprawnie na stronach z danymi wrażliwymi (no-store)
41. Clear-Site-Data obecny na endpoint logout
42. Expect-CT obecny (jeśli dotyczy)
43. Brak zduplikowanych nagłówków w odpowiedzi
44. Nagłówki bezpieczeństwa spójne między wersją HTTP i HTTPS strony

**2. Cookies** (test wykonywany osobno dla każdego znalezionego ciasteczka)
45. Cookie ma flagę Secure
46. Cookie ma flagę HttpOnly
47. Cookie ma ustawione SameSite=Strict lub Lax
48. Cookie z SameSite=None ma jednocześnie Secure
49. Czas życia cookie nie jest nadmiernie długi dla cookies sesyjnych
50. Cookie ma prefiks `__Host-` lub `__Secure-` tam gdzie zasadne
51. Nazwa cookie nie ujawnia technologii backendu (np. PHPSESSID, JSESSIONID wprost)
52. Domain scope cookie nie jest szerszy niż potrzeba
53. Path scope cookie nie jest szerszy niż potrzeba
54. Wartość cookie sesyjnego ma wystarczającą entropię (długość/losowość)

**3. TLS/SSL** (przez wrapper na testssl.sh)
55. SSLv2 wyłączony
56. SSLv3 wyłączony
57. TLS 1.0 wyłączony
58. TLS 1.1 wyłączony
59. TLS 1.2 wspierany
60. TLS 1.3 wspierany
61. Cipher RC4 niedostępny
62. Cipher DES niedostępny
63. Cipher 3DES niedostępny
64. Cipher NULL niedostępny
65. Cipher EXPORT niedostępny
66. Cipher anon-DH niedostępny
67. Forward secrecy (ECDHE/DHE) obecne
68. Certyfikat nie wygasł
69. Certyfikat nie wygasa w ciągu 30 dni (warning)
70. Certificate chain jest kompletny
71. Certyfikat nie jest self-signed
72. Wildcard certyfikatu nie jest nadmiernie szeroki
73. SAN (Subject Alternative Names) zawiera poprawną domenę
74. Hostname zgadza się z certyfikatem
75. Rozmiar klucza RSA ≥ 2048 bitów lub ECC ≥ 256 bitów
76. Podatność Heartbleed nieobecna
77. Podatność POODLE nieobecna
78. Podatność BEAST nieobecna
79. Podatność CRIME nieobecna
80. Podatność FREAK nieobecna
81. Podatność Logjam nieobecna
82. Podatność ROBOT nieobecna
83. Podatność Sweet32 nieobecna
84. OCSP stapling obecny
85. Certificate Transparency (CT) log obecny
86. Mechanizm rewokacji (CRL/OCSP) skonfigurowany
87. Session resumption skonfigurowane bezpiecznie
88. Renegocjacja TLS jest bezpieczna (secure renegotiation)
89. Kompresja TLS wyłączona (ochrona przed CRIME)

**4. DNS i domena**
90. Rekord SPF obecny
91. Rekord SPF ma poprawną składnię
92. Rekord SPF nie jest nadmiernie permisywny (`~all`/`-all` zamiast `+all`)
93. Rekord DKIM obecny (per znaleziony selector)
94. Rekord DMARC obecny
95. Polityka DMARC ustawiona na `quarantine` lub `reject` (nie `none`)
96. DMARC `pct` ustawiony na 100
97. DMARC ma skonfigurowane `rua`/`ruf` (raportowanie)
98. DNSSEC obecny
99. Łańcuch walidacji DNSSEC jest poprawny
100. Rekord CAA obecny
101. CAA ogranicza dozwolonych wystawców certyfikatów
102. Brak wildcard DNS ujawniającego nieistniejące subdomeny
103. Transfer strefy (AXFR) niemożliwy z zewnątrz
104. Enumeracja subdomen (lista znalezionych, per subdomena test dostępności)
105. Wykrycie "dangling DNS" (subdomena wskazująca na nieistniejący zasób = ryzyko subdomain takeover)
106. Rekordy MX mają sensowną konfigurację
107. Rekordy NS mają redundancję (min. 2 serwery)
108. TTL rekordów jest sensowny (nie ekstremalnie niski/wysoki)
109. Reverse DNS (PTR) skonfigurowany poprawnie
110. Data wygaśnięcia domeny nie jest bliska (warning)
111. WHOIS privacy/ochrona danych rejestranta włączona

**5. Infrastruktura i porty** (przez wrapper na nmap, per znaleziony port)
112. Identyfikacja usługi na każdym otwartym porcie poza 80/443
113. Banner grabbing na każdym otwartym porcie
114. FTP: anonymous login niemożliwy
115. SSH: brak słabych algorytmów wymiany kluczy
116. SSH: wersja nie jest ujawniona nadmiernie
117. Telnet: port nieotwarty (krytyczne jeśli otwarty)
118. SMTP: open relay niemożliwy
119. RDP: port niewystawiony publicznie
120. MySQL (3306): port niewystawiony publicznie
121. PostgreSQL (5432): port niewystawiony publicznie
122. MongoDB (27017): port niewystawiony publicznie
123. Redis (6379): port niewystawiony publicznie
124. Elasticsearch (9200): port niewystawiony publicznie
125. Memcached: port niewystawiony publicznie
126. Directory listing wyłączony
127. Ścieżka `.git/` niedostępna publicznie
128. Ścieżka `.svn/` niedostępna publicznie
129. Plik `.env` niedostępny publicznie
130. Plik `.DS_Store` niedostępny publicznie
131. Pliki backup (`.bak`, `.old`, `.zip`, `.sql`) niedostępne publicznie
132. Pliki konfiguracyjne (`web.config`, `wp-config.php.bak`) niedostępne publicznie
133. Panel `/wp-admin` niedostępny bez potrzeby lub odpowiednio zabezpieczony
134. Panel `/phpmyadmin` niedostępny publicznie
135. Panel `/admin` sprawdzony pod kątem domyślnych danych logowania
136. WAF wykryty i zidentyfikowany (info)
137. CDN wykryty i zidentyfikowany (info)
138. Zawartość `robots.txt` nie ujawnia wrażliwych ścieżek
139. Zawartość `sitemap.xml` przeanalizowana
140. Plik `security.txt` obecny (dobra praktyka)
141. Plik `humans.txt` (info)
142. Fingerprinting przez hash favicon.ico (identyfikacja stacku)

**6. HTTP Methods i protokół**
143. Metoda TRACE wyłączona (ochrona przed XST)
144. Metoda PUT wyłączona lub zabezpieczona autoryzacją
145. Metoda DELETE wyłączona lub zabezpieczona autoryzacją
146. Metoda CONNECT niedostępna publicznie
147. Response na OPTIONS nie ujawnia nadmiaru metod
148. Fallback do HTTP/1.0 sprawdzony
149. Wsparcie HTTP/2 sprawdzone
150. Wsparcie HTTP/3 (QUIC) sprawdzone
151. Wskaźniki request smuggling (niespójność Content-Length/Transfer-Encoding między proxy a serwerem)
152. Wskaźniki response splitting
153. Header injection przez CRLF w parametrach (wykrywanie, nie exploitacja)
154. Podatność na Host header injection (wykrywanie)
155. Obsługa absolute-URI w request line
156. Poprawna obsługa chunked encoding
157. Konflikt Content-Length vs Transfer-Encoding wykryty

**7. Kompresja i cache**
158. Wskaźniki podatności BREACH (kompresja + reflected input w odpowiedzi)
159. Konfiguracja gzip/brotli poprawna
160. Wskaźniki cache poisoning (unkeyed headers wpływające na cache)
161. Nagłówek Vary skonfigurowany poprawnie
162. ETag nie ujawnia informacji o inode/wersji pliku
163. Konfiguracja `stale-while-revalidate` sprawdzona
164. Cache-Control na endpointach API nie cache'uje danych wrażliwych
165. CDN nie cache'uje odpowiedzi z danymi wrażliwymi

**8. Fingerprinting technologii** (przez wrapper na whatweb)
166. Wykrycie CMS (WordPress/Joomla/Drupal/inne)
167. Wykrycie frameworku frontendowego i jego wersji
168. Wykrycie języka/frameworku server-side
169. Wykrycie każdej biblioteki JS i jej wersji (per biblioteka osobny test)
170. Enumeracja pluginów CMS (per plugin, sprawdzenie wersji vs baza CVE)
171. Wykrycie load balancera
172. Inwentaryzacja skryptów analytics/tracking
173. Obecność SRI (Subresource Integrity) na każdym zewnętrznym skrypcie
174. Wykrycie dostawcy fontów/CDN
175. Ekspozycja source maps JS

**9. Formularze i input handling**
176. Obecność tokenu CSRF w każdym formularzu POST
177. `autocomplete=off` na polach haseł
178. Rate limiting na formularzu logowania (test przez throttled requests)
179. Rate limiting na formularzu rejestracji
180. Rate limiting na formularzu resetu hasła
181. Obecność CAPTCHA na formularzach publicznych
182. Formularz wysyła dane po HTTPS (action nie wskazuje na HTTP)
183. Brak wrażliwych danych przesyłanych metodą GET
184. Pole hasła ma type="password"
185. Walidacja typu pliku przy uploadzie po stronie serwera (nie tylko client-side)
186. Obecność honeypot fields (info, nie wymagane)
187. `autocomplete=off` na polach numeru karty płatniczej
188. Limity długości pól input obecne po stronie serwera
189. Weryfikacja czy walidacja nie istnieje wyłącznie po stronie klienta

**10. Sesje i uwierzytelnianie**
190. Session ID nie jest przekazywany w URL
191. Session fixation: ID sesji zmienia się po zalogowaniu
192. Wylogowanie unieważnia sesję po stronie serwera
193. Timeout sesji jest skonfigurowany
194. Obsługa równoczesnych sesji sprawdzona
195. Token resetu hasła ma odpowiednią entropię
196. Token resetu hasła ma czas wygaśnięcia
197. Token "zapamiętaj mnie" jest bezpiecznie generowany
198. Dostępność uwierzytelniania dwuskładnikowego (info)
199. Blokada konta po serii nieudanych prób logowania
200. Komunikaty błędu logowania nie ujawniają czy dany użytkownik istnieje
201. JWT: algorytm `none` nie jest akceptowany
202. JWT: brak wskaźników słabego sekretu podpisu
203. JWT: pole `exp` obecne
204. JWT: pole `iat` obecne
205. JWT: podpis jest faktycznie walidowany przez serwer (test przez podstawienie zmodyfikowanego tokenu)
206. Polityka siły hasła widoczna z formularza (info)

**11. Redirecty i mixed content**
207. Przekierowanie HTTP→HTTPS wymuszone
208. Brak mixed content: obrazy ładowane po HTTP na stronie HTTPS
209. Brak mixed content: skrypty ładowane po HTTP
210. Brak mixed content: arkusze CSS ładowane po HTTP
211. Brak mixed content: iframe ładowany po HTTP
212. Brak mixed content: czcionki ładowane po HTTP
213. Brak podatności open redirect w parametrze `redirect`
214. Brak podatności open redirect w parametrze `url`
215. Brak podatności open redirect w parametrze `next`
216. Długość łańcucha przekierowań nie jest nadmierna
217. Canonical URL ustawiony poprawnie
218. Meta-refresh redirect nie prowadzi do niezaufanej domeny

**12. Informacje ujawniane w kodzie**
219. Brak komentarzy HTML zawierających wrażliwą treść
220. Brak kluczy API w kodzie JS (skan przez regex)
221. Brak wewnętrznych adresów IP/hostname w odpowiedziach
222. Brak stack trace w odpowiedzi 404
223. Brak stack trace w odpowiedzi 500 (wymuszona przez malformed input)
224. Source maps JS nie są publicznie dostępne
225. Brak wpisów TODO/FIXME z wrażliwą treścią w dostępnym kodzie
226. Brak ścieżek systemowych w komunikatach błędów
227. Odpowiedź na malformed input nie jest nadmiernie szczegółowa
228. Brak ujawnionych nazw wewnętrznych serwisów/mikroserwisów
229. Tryb debug wyłączony (wskaźniki Django DEBUG=True)
230. Tryb debug wyłączony (wskaźniki Laravel APP_DEBUG=true)
231. Dokumentacja Swagger/OpenAPI nie jest publicznie dostępna bez autoryzacji

**13. CORS**
232. Access-Control-Allow-Origin nie jest `*` na endpointach z danymi wrażliwymi
233. ACAO nie odbija dowolnego Origin (reflection check)
234. ACAO=`*` nie występuje jednocześnie z Allow-Credentials=true
235. Odpowiedź na preflight (OPTIONS) jest poprawna
236. Dozwolone metody w CORS nie są nadmiarowe
237. Dozwolone nagłówki w CORS nie są nadmiarowe
238. Origin `null` nie jest akceptowany

**14. API / GraphQL** (jeśli wykryte)
239. GraphQL introspection wyłączone w produkcji
240. GraphQL: batching zapytań ma limit (ochrona przed DoS)
241. Endpointy REST wymagają autoryzacji tam gdzie powinny
242. Wersjonowanie API nie ujawnia niepotrzebnie starych, niezabezpieczonych wersji
243. Rate limiting obecny na endpointach API
244. Klucz API nie jest przekazywany w URL zamiast w nagłówku
245. Dokumentacja Swagger/OpenAPI zabezpieczona autoryzacją
246. Brak wskaźników mass assignment (przyjmowanie nadmiarowych pól w body)
247. Wskaźniki IDOR: sekwencyjne ID w odpowiedziach API (pasywna obserwacja, bez exploitacji)
248. Komunikaty błędów API nie są nadmiernie szczegółowe

**15. WebSocket** (jeśli wykryte)
249. Połączenie WebSocket używa `wss://` (szyfrowane), nie `ws://`
250. Walidacja nagłówka Origin przy handshake
251. Token uwierzytelniający nie jest przekazywany w URL WebSocket
252. Rate limiting obecny na wiadomościach WebSocket
253. Limit rozmiaru wiadomości WebSocket ustawiony
254. Wskaźniki podatności CSWSH (cross-site WebSocket hijacking)

**16. Prywatność / zgodność**
255. Baner zgody na cookies obecny
256. Trackery firm trzecich nie ładują się przed wyrażeniem zgody
257. Link do polityki prywatności obecny
258. Informacja o możliwości żądania danych (GDPR) obecna
259. Obsługa nagłówka Do Not Track sprawdzona
260. Google Analytics/Facebook Pixel nie ładują się bez zgody
261. Zewnętrzne fonty (np. Google Fonts) ładowane z uwzględnieniem prywatności
262. Dane z formularzy nie są wysyłane do stron trzecich bez wskazania tego użytkownikowi
263. Baner zgody faktycznie blokuje trackery, a nie tylko ukrywa UI

**17. Supply chain / third-party**
264. SRI obecne na każdym zewnętrznym skrypcie (per zasób)
265. SRI obecne na każdym zewnętrznym arkuszu stylów (per zasób)
266. Domeny zewnętrznych zasobów sprawdzone pod kątem znanej reputacji
267. Liczba i pochodzenie zewnętrznych zasobów zinwentaryzowane (info)
268. Każda przestarzała biblioteka JS sprawdzona względem bazy CVE (per biblioteka)
269. Plik `package-lock.json`/`composer.lock` niedostępny publicznie
270. Plik `package.json` niedostępny publicznie
271. Zawartość `.well-known/` sprawdzona
272. Zewnętrzne iframe mają atrybut `sandbox`

**18. Business logic — sygnały pasywne**
273. Sekwencyjne identyfikatory w URL/API (wskaźnik ryzyka IDOR)
274. Endpointy z listami danych mają limit paginacji (ochrona przed scrapingiem/DoS)
275. Pola ceny/ilości nie są edytowalne po stronie klienta bez walidacji serwera (info)
276. Endpoint kuponu/promocji ma rate limiting
277. Kroki procesu (np. checkout) nie da się pominąć przez bezpośredni URL (info)

Łącznie: **277 osobno zaimplementowanych testów bazowych** (część z nich mnoży się dodatkowo
przez liczbę znalezionych cookies/portów/subdomen/bibliotek/pluginów na konkretnej stronie,
więc realna liczba wykonanych sprawdzeń na typowym skanie będzie wyższa).

### Wymagania jakościowe
- Każdy moduł testowy w osobnym pliku, jeden test = jedna, mała, testowalna funkcja
- Pisz testy jednostkowe (pytest) dla logiki parsującej (np. parsowanie CSP), nie dla realnych requestów sieciowych
- Rate-limituj własne requesty do celu (nie zamieniaj audytu w DoS)
- Wszystko z opcją `--dry-run` i jasnym logiem co się dzieje
- Konfiguracja przez `.env` (brak sekretów w kodzie)
- README z instrukcją uruchomienia i wyraźnym disclaimerem prawnym (tylko za zgodą właściciela domeny)

### Zasady pracy i commity — PRZESTRZEGAJ ŚCIŚLE
- Rób commity po każdym ukończonym, działającym kawałku funkcjonalności (atomowe commity) —
  nie czekaj do końca całej sesji z jednym wielkim commitem
- Format: Conventional Commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`)
  np. `feat(headers): add CSP unsafe-inline detection test`
- Commituj i pushuj na `origin/main` od razu po każdym commicie, nie zostawiaj niewypchniętych zmian
- NIE dodawaj stopki `Co-authored-by` ani żadnej wzmianki o AI w treści commita
- Git identity: użyj lokalnej konfiguracji repo (user.name = DolilDev)
- Przed commitem uruchom istniejące testy jednostkowe — jeśli coś nie przechodzi, napraw przed commitem
- Pisz commit message w języku angielskim, krótko i konkretnie, bez opisowego marketingowego tonu

Zacznij od: szkieletu projektu (struktura katalogów, FastAPI skeleton, docker-compose z Postgres+Redis),
zrób pierwszy commit `chore: initial project scaffold`, a potem przejdź do modułu 1 (HTTP Security Headers).

---

## KONIEC PROMPTU

### Uwaga dodatkowa (nie wklejaj tego do Copilota, to dla Ciebie)
Warto to rozbić na kilka sesji/promptów zamiast jednego mega-requestu — Copilot Chat w trybie agenta
czasem "gubi się" przy bardzo długich zadaniach. Możesz np. po zbudowaniu szkieletu i modułu 1
dać osobny prompt: "przejdź teraz do modułu 2 (Cookies), trzymając się tych samych zasad co wcześniej".
