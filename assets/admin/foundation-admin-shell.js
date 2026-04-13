(function () {
  var wpElement = window.wp && window.wp.element;
  if (!wpElement) {
    return;
  }

  var h = wpElement.createElement;
  var useEffect = wpElement.useEffect;
  var useMemo = wpElement.useMemo;
  var useState = wpElement.useState;

  function cx() {
    return Array.prototype.slice.call(arguments).filter(Boolean).join(' ');
  }

  function getTemplateHtml(id) {
    var node = document.getElementById(id);
    return node ? node.innerHTML : '';
  }

  function fireReady(plugin) {
    window.dispatchEvent(new CustomEvent('foundation-admin:ready', {
      detail: { plugin: plugin || 'foundation' }
    }));
  }

  function MetricCard(props) {
    return h(
      'article',
      { className: cx('foundation-metric-card', props.tone && ('is-' + props.tone)) },
      h('span', { className: 'foundation-metric-label' }, props.label),
      h('strong', { className: 'foundation-metric-value' }, props.value),
      props.meta ? h('p', { className: 'foundation-metric-meta' }, props.meta) : null
    );
  }

  function ActionLink(props) {
    return h(
      'a',
      {
        className: cx('foundation-shell-button', props.variant === 'ghost' ? 'is-ghost' : 'is-solid'),
        href: props.href || '#',
        target: props.target || undefined,
        rel: props.target === '_blank' ? 'noreferrer noopener' : undefined
      },
      props.label
    );
  }

  function NavButton(props) {
    return h(
      'button',
      {
        type: 'button',
        className: 'foundation-nav-button',
        onClick: function () {
          var section = document.getElementById(props.targetId);
          if (section) {
            section.scrollIntoView({ behavior: 'smooth', block: 'start' });
            if (window.history && window.history.replaceState) {
              window.history.replaceState({}, '', '#' + props.targetId);
            }
          }
        }
      },
      props.children
    );
  }

  function HtmlBlock(props) {
    return h('div', {
      className: 'foundation-admin-rich',
      dangerouslySetInnerHTML: { __html: props.html || '' }
    });
  }

  function Section(props) {
    return h(
      'section',
      { id: props.id, className: 'foundation-shell-section foundation-shell-panel' },
      h(
        'header',
        { className: 'foundation-shell-section__header' },
        h('div', null,
          h('p', { className: 'foundation-shell-kicker' }, props.eyebrow || 'Workspace'),
          h('h2', { className: 'foundation-shell-section__title' }, props.title)
        ),
        props.description ? h('p', { className: 'foundation-shell-section__description' }, props.description) : null
      ),
      h(HtmlBlock, { html: props.html })
    );
  }

  var config = window.foundationAdminShellData || {};
  var target = document.getElementById(config.rootId || 'foundation-admin-app');
  if (!target) {
    return;
  }

  function App() {
    var sections = useMemo(function () {
      return (config.sections || []).map(function (section) {
        return Object.assign({}, section, {
          html: section.html || getTemplateHtml(section.templateId)
        });
      });
    }, []);
    var metrics = config.metrics || [];
    var actions = config.actions || [];
    var storageKey = config.themeStorageKey || 'foundation-admin-theme';
    var initialTheme = config.defaultTheme === 'dark' ? 'dark' : 'light';

    try {
      var savedTheme = window.localStorage.getItem(storageKey);
      if (savedTheme === 'dark' || savedTheme === 'light') {
        initialTheme = savedTheme;
      }
    } catch (err) {
      initialTheme = 'light';
    }

    var _useState = useState(initialTheme),
      theme = _useState[0],
      setTheme = _useState[1];

    useEffect(function () {
      try {
        window.localStorage.setItem(storageKey, theme);
      } catch (err) {
        // noop
      }
    }, [theme, storageKey]);

    useEffect(function () {
      window.requestAnimationFrame(function () {
        fireReady(config.plugin);
      });
    }, []);

    return h(
      'div',
      { className: cx('foundation-app-root', theme === 'dark' && 'is-dark') },
      h(
        'section',
        { className: 'foundation-shell-hero' },
        h(
          'div',
          { className: 'foundation-shell-hero__copy' },
          h('span', { className: 'foundation-shell-eyebrow' }, config.eyebrow || 'Foundation Admin'),
          h('div', { className: 'foundation-shell-hero__toolbar' },
            h('h1', { className: 'foundation-shell-title' }, config.title || 'Foundation'),
            h(
              'button',
              {
                type: 'button',
                className: 'foundation-shell-theme',
                onClick: function () {
                  setTheme(theme === 'dark' ? 'light' : 'dark');
                }
              },
              theme === 'dark' ? 'Light mode' : 'Dark mode'
            )
          ),
          config.description ? h('p', { className: 'foundation-shell-description' }, config.description) : null,
          config.badge ? h('span', { className: 'foundation-shell-badge' }, config.badge) : null,
          actions.length ? h(
            'div',
            { className: 'foundation-shell-actions' },
            actions.map(function (action) {
              return h(ActionLink, { key: action.label, label: action.label, href: action.href, target: action.target, variant: action.variant });
            })
          ) : null
        ),
        metrics.length ? h(
          'div',
          { className: 'foundation-shell-metrics' },
          metrics.map(function (metric) {
            return h(MetricCard, {
              key: metric.label,
              label: metric.label,
              value: metric.value,
              meta: metric.meta,
              tone: metric.tone
            });
          })
        ) : null
      ),
      sections.length ? h(
        'nav',
        { className: 'foundation-shell-nav', 'aria-label': 'Section navigation' },
        sections.map(function (section) {
          return h(
            NavButton,
            { key: section.id, targetId: section.id },
            section.navLabel || section.title
          );
        })
      ) : null,
      h(
        'div',
        { className: 'foundation-shell-sections' },
        sections.map(function (section) {
          return h(Section, {
            key: section.id,
            id: section.id,
            eyebrow: section.eyebrow,
            title: section.title,
            description: section.description,
            html: section.html
          });
        })
      )
    );
  }

  if (typeof wpElement.createRoot === 'function') {
    wpElement.createRoot(target).render(h(App));
  } else {
    wpElement.render(h(App), target);
  }
})();
