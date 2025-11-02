// static/js/theme.js
(function () {
  const KEY = 'theme';
  const html = document.documentElement; // <html>
  const body = document.body;

  // اقرأ تفضيل النظام (للتحميل الأول فقط إذا ما فيه اختيار محفوظ)
  const sysDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

  // اختيار المستخدم (إن وُجد)
  const saved = localStorage.getItem(KEY);
  const initial = (saved === 'dark' || saved === 'light') ? saved : (sysDark ? 'dark' : 'light');

  function applyTheme(theme, { persist = true } = {}) {
    const isDark = theme === 'dark';
    html.setAttribute('data-theme', theme);
    body.classList.toggle('dark', isDark);

    // لو عندك زر
    const btn = document.getElementById('theme-toggle') || document.querySelector('.theme-fab');
    if (btn) {
      // اكسسبيليتي
      btn.setAttribute('aria-pressed', String(isDark));
      // غيّري الرمز حسب رغبتك
      if (btn.tagName === 'BUTTON') btn.textContent = isDark ? '☀️' : '🌙';
    }

    if (persist) localStorage.setItem(KEY, theme);
  }

  // طبّقي الثيم المبدئي
  applyTheme(initial, { persist: saved === 'dark' || saved === 'light' });

  // استمعي لتغيّر تفضيل النظام فقط إذا المستخدم ما اختار يدويًا بعد
  if (!saved && window.matchMedia) {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    mq.addEventListener?.('change', (e) => {
      applyTheme(e.matches ? 'dark' : 'light');
    });
  }

  // زر التبديل
  const toggle = document.getElementById('theme-toggle') || document.querySelector('.theme-fab');
  if (toggle) {
    toggle.addEventListener('click', () => {
      const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      applyTheme(next);
    });
  }

  // مزامنة بين التبويبات
  window.addEventListener('storage', (e) => {
    if (e.key === KEY && (e.newValue === 'dark' || e.newValue === 'light')) {
      applyTheme(e.newValue, { persist: false });
    }
  });
})();
