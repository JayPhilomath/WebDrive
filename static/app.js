// WebDrive front end.
//
// Wrapped in an IIFE so nothing leaks onto window. There is no build step and
// no framework, so plain DOM calls throughout.
(function () {
  // -------------------------------------------------------------------------
  // SECTION: config, dom handles, state
  // -------------------------------------------------------------------------

  // Server config arrives in a <script type="application/json"> block rather
  // than an inline script, so the CSP can stay on script-src 'self'.
  const CONFIG = JSON.parse(document.getElementById("app-config").textContent);

  const fileListTbody = document.getElementById("file-list");
  const breadcrumbsEl = document.getElementById("breadcrumbs");
  const refreshBtn = document.getElementById("refresh-btn");
  const pasteBtn = document.getElementById("paste-btn");
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("file-input");
  const progressBar = document.getElementById("progress-bar");
  const progressText = document.getElementById("progress-text");
  const themeToggle = document.getElementById("theme-toggle");
  const actionStatus = document.getElementById("action-status");

  const state = {
    currentPath: decodePathFromHash(location.hash) || "",
    pollingId: null,
    theme: loadThemePreference(),
  };

  // -------------------------------------------------------------------------
  // SECTION: init, polling
  // -------------------------------------------------------------------------

  initialize().catch((error) => {
    console.error(error);
    setActionStatus(error.message || "Initialization failed", "error");
  });

  async function initialize() {
    await loadThemeTokens();
    applyTheme(state.theme);
    applyClipboardState();
    bindEvents();
    // Polling, not websockets. Another device adding a file should show up
    // without a manual refresh, and 3s is frequent enough to feel immediate
    // while staying cheap on a directory listing.
    state.pollingId = setInterval(refresh, 3000);
    await refresh();
  }

  // -------------------------------------------------------------------------
  // SECTION: event binding, drag and drop, paste, theme toggle
  // -------------------------------------------------------------------------

  function bindEvents() {
    refreshBtn.addEventListener("click", () => refresh());
    window.addEventListener("hashchange", onHashChange);

    themeToggle.addEventListener("click", () => {
      state.theme = state.theme === "dark" ? "light" : "dark";
      saveThemePreference(state.theme);
      applyTheme(state.theme);
    });

    // Paste button. Reads the clipboard directly, which needs permission and a
    // secure context. See applyClipboardState below.
    pasteBtn.addEventListener("click", async () => {
      try {
        const files = [];
        const ts = tsStamp();
        if (navigator.clipboard && navigator.clipboard.read) {
          const items = await navigator.clipboard.read();
          for (const item of items) {
            for (const type of item.types) {
              if (type.startsWith("image/")) {
                const blob = await item.getType(type);
                const ext = guessExt(type) || ".png";
                files.push(new File([blob], `pasted-${ts}${ext}`, { type }));
              } else if (type === "text/plain") {
                const blob = await item.getType(type);
                files.push(new File([blob], `pasted-${ts}.txt`, { type }));
              }
            }
          }
        } else if (navigator.clipboard && navigator.clipboard.readText) {
          // Older browsers expose readText but not read.
          const text = await navigator.clipboard.readText();
          if (text && text.trim()) {
            const blob = new Blob([text], { type: "text/plain" });
            files.push(new File([blob], `pasted-${ts}.txt`, { type: "text/plain" }));
          }
        }

        if (!files.length) {
          alert("Clipboard is empty or permission was denied. Try Ctrl/Cmd+V.");
          return;
        }

        await uploadFiles(files);
      } catch (error) {
        alert("Clipboard access failed. Try Ctrl/Cmd+V to paste instead.");
      }
    });

    // preventDefault on all four events, otherwise the browser navigates away
    // to the dropped file instead of handing it over.
    ["dragenter", "dragover"].forEach((eventName) => {
      dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        event.stopPropagation();
        dropzone.classList.add("dropzone-active");
      });
    });

    ["dragleave", "drop"].forEach((eventName) => {
      dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        event.stopPropagation();
        dropzone.classList.remove("dropzone-active");
      });
    });

    dropzone.addEventListener("drop", (event) => {
      const files = event.dataTransfer ? event.dataTransfer.files : [];
      uploadFiles(files).catch((error) => alert(error.message || String(error)));
    });

    fileInput.addEventListener("change", () => {
      const files = fileInput.files || [];
      uploadFiles(files).catch((error) => alert(error.message || String(error)));
      // Reset so picking the same file twice in a row still fires change.
      fileInput.value = "";
    });

    // Ctrl/Cmd+V path. Reads event.clipboardData, which needs no permission and
    // no secure context, so this keeps working over plain HTTP where the paste
    // button does not.
    window.addEventListener("paste", async (event) => {
      try {
        const items = event.clipboardData && event.clipboardData.items ? Array.from(event.clipboardData.items) : [];
        if (!items.length) {
          return;
        }

        const files = [];
        const ts = tsStamp();
        for (const item of items) {
          if (item.kind === "file") {
            const file = item.getAsFile();
            if (file) {
              const ext = guessExt(file.type) || ".bin";
              files.push(new File([file], `pasted-${ts}${ext}`, { type: file.type || "application/octet-stream" }));
            }
          } else if (item.kind === "string") {
            const text = await new Promise((resolve) => item.getAsString(resolve));
            if (text && text.trim()) {
              const blob = new Blob([text], { type: "text/plain" });
              files.push(new File([blob], `pasted-${ts}.txt`, { type: "text/plain" }));
            }
          }
        }

        // Only swallow the paste if something was actually taken from it,
        // otherwise normal pasting into inputs breaks.
        if (files.length) {
          await uploadFiles(files);
          event.preventDefault();
        }
      } catch (error) {
        console.warn("Paste handling failed", error);
      }
    });
  }

  // -------------------------------------------------------------------------
  // SECTION: secure context, clipboard availability
  // -------------------------------------------------------------------------

  // navigator.clipboard.read only exists in a secure context. https:// and
  // http://localhost count, http://<lan-ip> does not, which is how this app is
  // normally reached. Checked up front so the button is disabled with a reason
  // rather than failing with an unclear error when clicked.
  function clipboardReadAvailable() {
    return Boolean(window.isSecureContext && navigator.clipboard && navigator.clipboard.read);
  }

  function applyClipboardState() {
    if (!clipboardReadAvailable()) {
      pasteBtn.disabled = true;
      pasteBtn.title = "Reading the clipboard needs HTTPS. Ctrl/Cmd+V still works.";
    }
  }

  // -------------------------------------------------------------------------
  // SECTION: url encoding, hash routing, navigation
  // -------------------------------------------------------------------------

  function csrfHeaderName() {
    return "X-CSRF-Token";
  }

  // Encode each segment separately. encodeURIComponent on the whole path would
  // escape the separators too and the server would see one long filename.
  function encodePathForUrl(path) {
    return path
      .split("/")
      .filter(Boolean)
      .map(encodeURIComponent)
      .join("/");
  }

  function decodePathFromHash(hash) {
    if (!hash) return "";
    const match = hash.match(/#p=(.*)$/);
    if (!match) return "";
    try {
      return match[1]
        .split("/")
        .filter(Boolean)
        .map(decodeURIComponent)
        .join("/");
    } catch {
      // Malformed percent-encoding in a hand-edited URL. Fall back to root.
      return "";
    }
  }

  function setHashFromPath(path) {
    const encoded = encodePathForUrl(path);
    if (encoded) {
      location.hash = `#p=${encoded}`;
      return;
    }
    // pushState rather than setting an empty hash, which would leave a bare "#"
    // in the address bar.
    history.pushState("", document.title, window.location.pathname + window.location.search);
  }

  function navigateTo(path) {
    state.currentPath = path || "";
    setHashFromPath(state.currentPath);
    refresh();
  }

  function onHashChange() {
    const path = decodePathFromHash(location.hash);
    if (path !== state.currentPath) {
      state.currentPath = path || "";
      refresh();
    }
  }

  // -------------------------------------------------------------------------
  // SECTION: listing, fetch, render, breadcrumbs
  // -------------------------------------------------------------------------

  async function fetchList() {
    const params = new URLSearchParams();
    if (state.currentPath) {
      params.set("p", state.currentPath);
    }
    const response = await fetch(`/api/list?${params.toString()}`, {
      headers: { Accept: "application/json" },
    });
    // The session can expire while the page sits open polling. 401 means send
    // the user back to log in rather than showing an error every 3 seconds.
    if (response.status === 401) {
      location.href = "/login";
      return null;
    }
    if (!response.ok) {
      throw new Error(`Failed to list files (${response.status})`);
    }
    return response.json();
  }

  function renderBreadcrumbs(cwd) {
    const segments = cwd ? cwd.split("/").filter(Boolean) : [];
    const crumbs = [{ name: CONFIG.shareRootName, path: "" }];
    const accum = [];
    for (const segment of segments) {
      accum.push(segment);
      crumbs.push({ name: segment, path: accum.join("/") });
    }

    breadcrumbsEl.innerHTML = crumbs
      .map((crumb, index) => {
        if (index === crumbs.length - 1) {
          return `<span class="crumb-current">${escapeHtml(crumb.name)}</span>`;
        }
        return `<a href="#" data-path="${escapeHtml(crumb.path)}">${escapeHtml(crumb.name)}</a>`;
      })
      .join('<span class="crumb-sep">/</span>');

    breadcrumbsEl.querySelectorAll("a[data-path]").forEach((anchor) => {
      anchor.addEventListener("click", (event) => {
        event.preventDefault();
        navigateTo(anchor.getAttribute("data-path") || "");
      });
    });
  }

  // Three columns, and the name itself is the link: a folder navigates, a file
  // downloads. No separate action column, which keeps the row close to a plain
  // directory index.
  //
  // Built with innerHTML, so every value taken from a filename goes through
  // escapeHtml first. Filenames are user-controlled and the server does not
  // alter them.
  function renderList(entries) {
    const rows = Array.isArray(entries) ? entries : [];

    if (!rows.length) {
      fileListTbody.innerHTML = '<tr class="empty-row"><td colspan="3">This folder is empty.</td></tr>';
      return;
    }

    fileListTbody.innerHTML = rows
      .map((entry) => {
        // File downloads are a plain href so the browser handles the transfer
        // itself, including large files and its own progress reporting.
        const nameCell = entry.is_dir
          ? `<a href="#" data-dir="${escapeHtml(entry.path)}">${escapeHtml(entry.name)}/</a>`
          : `<a href="/d/${encodePathForUrl(entry.path)}">${escapeHtml(entry.name)}</a>`;
        const sizeCell = entry.is_dir ? "-" : escapeHtml(entry.size_human || "");
        const modifiedCell = escapeHtml(entry.mtime_iso || "");
        return `<tr>
          <td class="cell-name">${nameCell}</td>
          <td>${sizeCell}</td>
          <td>${modifiedCell}</td>
        </tr>`;
      })
      .join("");

    // Rebound every render because innerHTML replaces the nodes. Listeners on
    // the old rows go with them, so there is nothing to clean up.
    fileListTbody.querySelectorAll("a[data-dir]").forEach((anchor) => {
      anchor.addEventListener("click", (event) => {
        event.preventDefault();
        navigateTo(anchor.getAttribute("data-dir") || "");
      });
    });
  }

  async function refresh() {
    try {
      const data = await fetchList();
      if (!data) {
        return;
      }
      renderBreadcrumbs(data.cwd || "");
      renderList(data.entries || []);
      if (data.root_name) {
        document.getElementById("share-root-name").textContent = data.root_name;
        CONFIG.shareRootName = data.root_name;
      }
      setActionStatus("", "");
    } catch (error) {
      console.error(error);
      setActionStatus(error.message || "Refresh failed", "error");
    }
  }

  // -------------------------------------------------------------------------
  // SECTION: upload, progress
  // -------------------------------------------------------------------------

  async function uploadFiles(filesLike) {
    const files = Array.from(filesLike || []);
    if (!files.length) {
      return;
    }

    const form = new FormData();
    files.forEach((file) => form.append("files", file, file.name));

    const params = new URLSearchParams();
    if (state.currentPath) {
      params.set("p", state.currentPath);
    }

    // XHR rather than fetch. fetch still has no upload progress event, and a
    // progress bar matters more here than the nicer API.
    await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `/api/upload?${params.toString()}`);
      xhr.setRequestHeader(csrfHeaderName(), CONFIG.csrfToken);
      xhr.upload.onprogress = (event) => {
        if (!event.lengthComputable) {
          return;
        }
        const percent = (event.loaded / event.total) * 100;
        setProgress(percent, `Uploading ${percent.toFixed(0)}%`);
      };
      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          setProgress(100, "Upload complete");
          resolve();
          return;
        }
        reject(new Error(`Upload failed (${xhr.status})`));
      };
      xhr.onerror = () => reject(new Error("Network error during upload"));
      xhr.send(form);
    });

    setActionStatus("Upload complete.", "success");
    setTimeout(() => setProgress(0, ""), 800);
    await refresh();
  }

  // -------------------------------------------------------------------------
  // SECTION: escaping, status, progress helpers
  // -------------------------------------------------------------------------

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function setProgress(percent, text) {
    const clamped = Math.max(0, Math.min(100, Math.round(percent || 0)));
    progressBar.style.width = `${clamped}%`;
    progressText.textContent = text || (clamped ? `${clamped}%` : "");
  }

  function setActionStatus(text, tone) {
    actionStatus.textContent = text || "";
    actionStatus.className = "status-text";
    if (!tone) {
      return;
    }
    actionStatus.classList.add(`status-${tone}`);
  }

  // -------------------------------------------------------------------------
  // SECTION: pasted file naming
  // -------------------------------------------------------------------------

  // Deliberately short. Pasted data has no filename, so this only needs to pick
  // an extension good enough for the file to open on the other device.
  function guessExt(mimeType) {
    if (!mimeType) return "";
    if (mimeType === "image/png") return ".png";
    if (mimeType === "image/jpeg") return ".jpg";
    if (mimeType === "image/webp") return ".webp";
    if (mimeType === "image/gif") return ".gif";
    if (mimeType.startsWith("text/")) return ".txt";
    return "";
  }

  // Local time, not ISO. These names are read by a person deciding which paste
  // was theirs, and UTC would be confusing for that.
  function tsStamp() {
    const date = new Date();
    const pad = (value) => String(value).padStart(2, "0");
    return (
      date.getFullYear().toString() +
      pad(date.getMonth() + 1) +
      pad(date.getDate()) +
      "-" +
      pad(date.getHours()) +
      pad(date.getMinutes()) +
      pad(date.getSeconds())
    );
  }

  // -------------------------------------------------------------------------
  // SECTION: theme, css variables
  // -------------------------------------------------------------------------

  function loadThemePreference() {
    const stored = localStorage.getItem("webdrive-theme");
    if (stored === "light" || stored === "dark") {
      return stored;
    }
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function saveThemePreference(theme) {
    localStorage.setItem("webdrive-theme", theme);
  }

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
  }

  // Tokens live in theme.json so colours can be changed without touching CSS.
  // Applied as custom properties on :root. Set through the CSSOM rather than a
  // style attribute, which the CSP would block.
  async function loadThemeTokens() {
    const response = await fetch("/static/theme.json", {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw new Error("Failed to load theme.json");
    }

    const theme = await response.json();
    const root = document.documentElement;
    const shared = theme.shared || {};
    const light = theme.light || {};
    const dark = theme.dark || {};

    Object.entries(shared).forEach(([key, value]) => root.style.setProperty(`--${key}`, String(value)));
    Object.entries(light).forEach(([key, value]) => root.style.setProperty(`--light-${key}`, String(value)));
    Object.entries(dark).forEach(([key, value]) => root.style.setProperty(`--dark-${key}`, String(value)));
  }
})();
