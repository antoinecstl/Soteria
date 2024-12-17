export default defineContentScript({
  matches: ['<all_urls>'],
  main() {
    // Définir les poids des critères restants
    const poids: { [key: string]: number } = {
      reputation: 70,
      ssl: 20,
      contact: 10
    };

    // Durée d'expiration du cache en millisecondes (24 heures)
    const CACHE_DURATION: number = 24 * 60 * 60 * 1000;

    (async () => {
      const url: string = window.location.href;
      const { total, details } = await calculerScoreConfiance(url);
      afficherScore(total, details);

      // Afficher le résultat de la requête RDAP dans la console web
      const rdapResult = await requeteRDAP(url);
      console.log('Résultat RDAP:', rdapResult);
    })();

    async function calculerScoreConfiance(url: string): Promise<{ total: number, details: { [key: string]: number } }> {
      const cachedData = await getCachedData(url);
      if (cachedData) {
        console.log('Utilisation des données en cache pour:', url);
        return cachedData;
      }

      const notes: { [key: string]: number } = {};

      // Vérifier le certificat SSL
      notes.ssl = verifierSSL(url) ? 100 : 0;

      // Vérifier la réputation du domaine via Google Safe Browsing
      notes.reputation = await verifierReputation(url);

      // Vérifier la présence d'informations de contact
      notes.contact = verifierContact(url) ? 100 : 0;

      // Calculer le score global avec une moyenne pondérée
      let score: number = 0;
      for (let critere in notes) {
        score += (notes[critere] * poids[critere]) / 100;
      }

      const result = { total: Math.round(score), details: notes };
      
      // Stocker les résultats dans le cache
      await setCachedData(url, result);

      return result;
    }

    async function requeteRDAP(url: string): Promise<{ creationDate: string, rawData?: any }> {
      try {
        const domain: string = new URL(url).hostname; // Extraire le domaine depuis l'URL
        const rdapEndpoint: string = `https://rdap.org/domain/${domain}`;
        const response: Response = await fetch(rdapEndpoint, {
          method: 'GET',
          headers: {
            'Accept': 'application/rdap+json'
          }
        });

        if (!response.ok) {
          throw new Error(`Erreur RDAP pour ${domain}: ${response.statusText}`);
        }

        const data = await response.json();
        const creationDate: string | undefined = data.events?.find((event: any) => event.eventAction === "registration")?.eventDate;

        return {
          creationDate: creationDate || "Date de création non disponible",
          rawData: data
        };
      } catch (error) {
        console.error("Erreur lors de la requête RDAP:", error);
        return { creationDate: "Erreur lors de la récupération des données RDAP" };
      }
    }

    function afficherScore(score: number, details: { [key: string]: number }) {
      // Vérifier si l'élément existe déjà pour éviter les duplications
      if (document.getElementById('score-confiance')) return;

      const scoreElement: HTMLDivElement = document.createElement('div');
      scoreElement.id = 'score-confiance';
      scoreElement.innerHTML = 
        `Score de confiance: ${score}%
        <div id="score-confiance-tooltip">
          <strong>Détails des analyses :</strong><br>
          Réputation : ${details.reputation}%<br>
          SSL : ${details.ssl}%<br>
          Contact : ${details.contact}%
        </div>`;

      document.body.appendChild(scoreElement);

      const style: HTMLStyleElement = document.createElement('style');
      style.innerHTML = 
        `#score-confiance {
          position: fixed;
          top: 10px;
          right: 10px;
          background-color: rgba(0, 0, 0, 0.7);
          color: #fff;
          padding: 10px 15px;
          border-radius: 5px;
          z-index: 10000;
          font-family: Arial, sans-serif;
          font-size: 14px;
          box-shadow: 0 2px 6px rgba(0,0,0,0.3);
          cursor: move;
          transition: background-color 0.3s, color 0.3s;
          user-select: none;
        }

        #score-confiance .close-button {
          position: absolute;
          top: 2px;
          right: 5px;
          font-size: 16px;
          cursor: pointer;
        }

        #score-confiance-tooltip {
          visibility: hidden;
          width: 200px;
          background-color: rgba(0, 0, 0, 0.9);
          color: #fff;
          text-align: left;
          border-radius: 5px;
          padding: 10px;
          position: absolute;
          top: 120%;
          right: 0;
          z-index: 10001;
          opacity: 0;
          transition: opacity 0.3s;
        }

        #score-confiance:hover #score-confiance-tooltip {
          visibility: visible;
          opacity: 1;
        }`;
      document.head.appendChild(style);

      // Ajouter le bouton de fermeture
      addCloseButton(scoreElement);

      // Ajuster les couleurs en fonction du fond de la page
      adjustScoreElementColors(scoreElement);

      // Rendre la bulle déplaçable
      makeElementDraggable(scoreElement);
    }

    function verifierSSL(url: string): boolean {
      try {
        const urlObj: URL = new URL(url);
        return urlObj.protocol === 'https:';
      } catch (e) {
        return false;
      }
    }

    async function verifierReputation(url: string): Promise<number> {
      const apiKey: string = 'AIzaSyAAmMyZ8Ol1bcChJm6-6hqJ1bIIhi-xBaA'; // Remplacez par votre clé API
      const endpoint: string = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
      const payload = {
        client: {
          clientId: "checker",
          clientVersion: "1.5.2"
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
          platformTypes: ["WINDOWS"],
          threatEntryTypes: ["URL"],
          threatEntries: [
            { url: url }
          ]
        }
      };

      try {
        const response: Response = await fetch(endpoint, {
          method: 'POST',
          body: JSON.stringify(payload),
          headers: {
            'Content-Type': 'application/json'
          }
        });
        const data = await response.json();
        return (data.matches && data.matches.length > 0) ? 0 : 100;
      } catch (error) {
        console.error('Erreur lors de la vérification de la réputation:', error);
        return 50; // Score neutre en cas d'erreur
      }
    }

    function verifierContact(url: string): boolean {
      // Utiliser le DOM pour chercher des éléments de contact
      const contactKeywords: string[] = ['contact', 'about', 'support', 'help'];
      const anchors: NodeListOf<HTMLAnchorElement> = document.querySelectorAll('a');
      for (let anchor of anchors) {
        for (let keyword of contactKeywords) {
          if (anchor.textContent.toLowerCase().includes(keyword) || anchor.href.toLowerCase().includes(keyword)) {
            return true;
          }
        }
      }
      return false;
    }

    // Fonction de mise en cache
    function getCachedData(url: string): Promise<{ total: number, details: { [key: string]: number } } | null> {
      return new Promise((resolve) => {
        chrome.storage.local.get([url], (result) => {
          if (result[url]) {
            const { timestamp, data } = result[url];
            const now: number = Date.now();
            if (now - timestamp < CACHE_DURATION) {
              resolve(data);
            } else {
              // Données expirées
              chrome.storage.local.remove([url], () => {
                resolve(null);
              });
            }
          } else {
            resolve(null);
          }
        });
      });
    }

    function setCachedData(url: string, data: { total: number, details: { [key: string]: number } }): Promise<void> {
      return new Promise((resolve) => {
        const timestamp: number = Date.now();
        const cacheEntry = { timestamp, data };
        const toStore: { [key: string]: any } = {};
        toStore[url] = cacheEntry;
        chrome.storage.local.set(toStore, () => {
          resolve();
        });
      });
    }

    // Fonction pour ajuster les couleurs en fonction du fond de la page
    function adjustScoreElementColors(element: HTMLElement) {
      const bodyStyles: CSSStyleDeclaration = window.getComputedStyle(document.body);
      let bgColor: string = bodyStyles.getPropertyValue('background-color');
      let brightness: number = getBrightness(bgColor);
      
      // Si la couleur de fond est transparente ou non définie, définir une valeur par défaut
      if (bgColor === 'rgba(0, 0, 0, 0)' || bgColor === 'transparent') {
        // Parcourir les éléments parents pour trouver une couleur de fond
        bgColor = getParentBackgroundColor(document.body);
        brightness = getBrightness(bgColor);
        console.log('Parent Background color:', bgColor);
        console.log('Parent Brightness:', brightness);
      }

      if (brightness < 128) { // Fond sombre
        element.style.backgroundColor = 'rgba(255, 255, 255, 0.8)';
        element.style.color = '#000';
      } else { // Fond clair
        element.style.backgroundColor = 'rgba(0, 0, 0, 0.8)';
        element.style.color = '#fff';
      }
    }

    function getBrightness(rgb: string): number {
      // Extraire les valeurs R, G, B
      const result: RegExpMatchArray | null = rgb.match(/\d+/g);
      if (!result || result.length < 3) return 255; // Par défaut clair

      const r: number = parseInt(result[0]);
      const g: number = parseInt(result[1]);
      const b: number = parseInt(result[2]);

      // Calcul de la luminosité selon la formule de ITU-R BT.601
      return Math.round((0.299 * r) + (0.587 * g) + (0.114 * b));
    }

    function getParentBackgroundColor(element: HTMLElement): string {
      let parent: HTMLElement | null = element.parentElement;
      while (parent) {
        const bgColor: string = window.getComputedStyle(parent).getPropertyValue('background-color');
        if (bgColor && bgColor !== 'rgba(0, 0, 0, 0)' && bgColor !== 'transparent') {
          return bgColor;
        }
        parent = parent.parentElement;
      }
      return 'rgba(255, 255, 255, 1)'; // Valeur par défaut si aucune couleur de fond n'est trouvée
    }

    // Fonction de fermeture de la bulle de score
    function addCloseButton(element: HTMLElement) {
      const closeButton: HTMLSpanElement = document.createElement('span');
      closeButton.className = 'close-button';
      closeButton.innerHTML = '&times;';
      element.appendChild(closeButton);

      closeButton.addEventListener('click', (e) => {
        e.stopPropagation(); // Empêche le déclenchement du drag ou du tooltip
        element.style.display = 'none';
      });
    }

    // Fonction pour rendre un élément draggable
    function makeElementDraggable(element: HTMLElement) {
      let isDragging: boolean = false;
      let offsetX: number = 0;
      let offsetY: number = 0;

      element.addEventListener('mousedown', (e) => {
        // Ignorer le drag si l'utilisateur clique sur le bouton de fermeture
        if (e.target.classList.contains('close-button')) {
          return;
        }

        isDragging = true;
        const rect: DOMRect = element.getBoundingClientRect();
        offsetX = e.clientX - rect.left;
        offsetY = e.clientY - rect.top;
        
        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);

        // Empêcher la sélection de texte pendant le drag
        e.preventDefault();
      });

      function onMouseMove(e: MouseEvent) {
        if (!isDragging) return;

        const newLeft: number = e.clientX - offsetX;
        const newTop: number = e.clientY - offsetY;

        element.style.left = `${newLeft}px`;
        element.style.top = `${newTop}px`;
        element.style.right = 'auto'; // Annule la position initiale
        element.style.bottom = 'auto'; // Annule la position initiale
      }

      function onMouseUp() {
        isDragging = false;
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
      }
    }
  },
});
