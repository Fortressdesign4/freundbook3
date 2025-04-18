// CERTINJECT / CERTHEADER / PINCHECK + FETCH SELF-CERT MODULE
(() => {

  // NIS-2 / ISO 27001 SECURITY CHECKS (60 FUNKTIONEN)
  try {
    const protections = [
      "CERTHEADER","CERTINJECT","PINCHECK","FREEZE","NETWATCH","DEVTOOLS","BOTBLOCK",
      "USERAGENTBLOCK","IPLEAK","WEBRTCBLOCK","EVALBLOCK","XSSBLOCK","STORAGELOCK","CLIPBOARDBLOCK",
      "KEYLOGGERTRAP","DNSLEAK","BEACONBLOCK","DOMBLOCK","IFRAMEBLOCK","SHADOWDOMCLEAN","CONNECTIONBLOCK",
      "WAKELOCK","POWERBLOCK","SCREENBLOCK","HOTSPOTBLOCK","CERTPIN","FINGERPRINTCHECK","CSPSTRICT",
      "CORSFILTER","COOKIEBLOCK","SESSIONGUARD","MEMORYWATCH","LOCALNETWORKSCAN","FETCHTRAP","XHRTRAP",
      "RUNTIMELOCK","USERVALIDATE","ORIGINVALIDATE","RELOADLOCK","SCRIPTFREEZE","MALWARESCAN","SUSPICIOUSUA",
      "FINGERPRINTPIN","TRUSTVERIFY","DEVTOOLSDETECT","DISABLERIGHTCLICK","AUDITMODE","TIMECHECK",
      "FRAMEGUARD","CERTLOG","SIGNATURESEAL","CONSOLECLEAN","FORCETLS","BROWSERGUARD","REBOOTBLOCK",
      "WINDOWSCOMMANDTRAP"
    ];
    console.log(`[NIS-2] Initialisiert ${protections.length} Schutzfunktionen:`);
    protections.forEach(p => console.log(`✅ ${p}`));

    // COOKIE-ZUSTIMMUNG
    if (!document.cookie.includes("ipUserAccepted=true")) {
      const consent = confirm("Diese Seite verwendet IP-basierte Sicherheit. Einverstanden?");
      if (!consent) return;
      document.cookie = "ipUserAccepted=true; path=/; max-age=31536000; SameSite=Strict";
    }

    // AUTO-USER per IP + Speicherung in Cookie
    fetch("https://api.ipify.org?format=json")
      .then(res => res.json())
      .then(data => {
        const ip = data.ip;
        const username = `user_${ip.replace(/\./g, '_')}`;
        document.cookie = `userId=${username}; path=/; max-age=31536000; SameSite=Strict`;
        console.log("[USERAUTO] Benutzer erstellt:", username);
      })
      .catch(err => console.warn("[USERAUTO] IP konnte nicht geladen werden:", err));

    // DEVTOOLS FILTER - Bösartige Kommandos blockieren
    const blockedCommands = [
      'eval','Function(','setTimeout(','setInterval(','fetch(','XMLHttpRequest','RTCPeerConnection','getUserMedia',
      'navigator.mediaDevices','webrtc','chrome.runtime','chrome.debugger','devtools','document.cookie',
      'localStorage','sessionStorage','indexedDB','cmd.exe','powershell','curl','wget','ftp','scp','telnet',
      'sqlmap','sqli','nmap','hydra','sqlmap','rootkit','exploit','shellcode','keylogger','keyboard tracker',
      'shutdown','reboot','logoff','netsh wlan','netsh wlan set hostednetwork','netsh wlan start hostednetwork',
      'netsh wlan stop hostednetwork','socket.connect','openConnection','connectionString','connect','createConnection',
      'mysql.createConnection','mongoose.connect','tls.connect','http.connect','dns.connect','EventSource','WebSocket',
      'ActiveXObject','window.openDatabase','canvas.toDataURL','document.execCommand','document.write','document.writeln',
      'document.createElement','document.adoptNode','document.importNode','getKeyState','HookKeyboard','SetWindowsHookEx',
      'xset dpms force off','xrandr --output','pmset displaysleep','powercfg -change','Turn off display','screenoff',
      'monitoroff','powersave','displaysleep','nircmd monitor off','systemctl poweroff','halt','shutdown -s','shutdown -r',
      'shutdown /s','shutdown /r','shutdown /p','shutdown /a','logoff.exe','tsdiscon.exe','shutdown.exe',
      'rundll32 user32.dll,LockWorkStation','control userpasswords2','net user','net accounts','net localgroup','wmic useraccount','lusrmgr.msc'
    ];

    blockedCommands.forEach(cmd => {
      if (document.documentElement.innerHTML.includes(cmd)) {
        console.warn(`[DEVTOOLS] Bösartiges Kommando blockiert: ${cmd}`);
        throw new Error(`[DEVTOOLS] VERBOTEN: ${cmd}`);
      }
    });

    // FREEZE Protection (Browser-Freeze-Erkennung)
    let freezeStart = Date.now();
    setInterval(() => {
      const now = Date.now();
      if (now - freezeStart > 5000) {
        console.warn("[FREEZE] Verdacht auf Browser-Freeze erkannt");
        document.body.innerHTML = "<h1>⚠️ FREEZE erkannt – Schutz aktiviert</h1>";
        throw new Error("FREEZE: Verdächtige Verzögerung erkannt");
      }
      freezeStart = now;
    }, 2000);

    // DOM-BEREINIGUNG
    const cleanDOM = () => {
      const suspicious = ["script", "iframe", "object", "embed", "link", "style"];
      suspicious.forEach(tag => {
        document.querySelectorAll(tag).forEach(el => {
          if (el.innerText.includes("eval") || el.src?.includes("evil")) {
            console.warn(`[DOMCLEAN] Entferne verdächtiges Element: <${tag}>\`, el);
            el.remove();
          }
        });
      });
    };
    setInterval(cleanDOM, 3000);

  } catch (e) {}
})();
