/* Architecture page behavior: flow tabs, rail scroll-spy, crate-graph focus. */
(() => {
  'use strict';

  /* ---------- Flow tabs ---------- */
  const flows = document.querySelector('[data-flows]');
  if (flows) {
    const tabs = Array.from(flows.querySelectorAll('[role="tab"]'));
    const panels = tabs.map((t) => document.getElementById(t.getAttribute('aria-controls')));

    const select = (tab) => {
      tabs.forEach((t, i) => {
        const on = t === tab;
        t.setAttribute('aria-selected', String(on));
        t.tabIndex = on ? 0 : -1;
        panels[i].hidden = !on;
      });
    };
    tabs.forEach((tab) => {
      tab.addEventListener('click', () => select(tab));
      tab.addEventListener('keydown', (e) => {
        const i = tabs.indexOf(tab);
        let next = null;
        if (e.key === 'ArrowRight') next = tabs[(i + 1) % tabs.length];
        if (e.key === 'ArrowLeft') next = tabs[(i - 1 + tabs.length) % tabs.length];
        if (e.key === 'Home') next = tabs[0];
        if (e.key === 'End') next = tabs[tabs.length - 1];
        if (next) { e.preventDefault(); next.focus(); select(next); }
      });
    });
    select(tabs[0]);
  }

  /* ---------- Rail scroll-spy ---------- */
  const rail = document.querySelector('[data-rail]');
  if (rail && 'IntersectionObserver' in window) {
    const links = Array.from(rail.querySelectorAll('a[href^="#"]'));
    const byId = new Map(links.map((a) => [a.getAttribute('href').slice(1), a]));
    const sections = links
      .map((a) => document.getElementById(a.getAttribute('href').slice(1)))
      .filter(Boolean);

    const setActive = (id) => {
      links.forEach((a) => a.classList.toggle('is-active', a === byId.get(id)));
    };
    const spy = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible.length) setActive(visible[0].target.id);
      },
      { rootMargin: '-20% 0px -60% 0px' }
    );
    sections.forEach((s) => spy.observe(s));
    setActive(sections[0]?.id);
  }

  /* ---------- Crate graph focus ---------- */
  const graph = document.querySelector('[data-crate-graph]');
  if (graph) {
    const nodes = Array.from(graph.querySelectorAll('g[data-crate]'));
    const edges = Array.from(graph.querySelectorAll('path[data-dep]'));

    const clear = () => {
      nodes.forEach((n) => n.classList.remove('is-dim', 'is-focus'));
      edges.forEach((e) => e.classList.remove('is-dim', 'is-focus'));
    };
    const focus = (name) => {
      const deps = new Set([name]);
      edges.forEach((e) => {
        const [from, to] = e.getAttribute('data-dep').split(':');
        if (from === name) deps.add(to);
      });
      nodes.forEach((n) => {
        const isDep = deps.has(n.getAttribute('data-crate'));
        n.classList.toggle('is-dim', !isDep);
        n.classList.toggle('is-focus', n.getAttribute('data-crate') === name);
      });
      edges.forEach((e) => {
        const isOut = e.getAttribute('data-dep').startsWith(name + ':');
        e.classList.toggle('is-focus', isOut);
        e.classList.toggle('is-dim', !isOut);
      });
    };

    nodes.forEach((n) => {
      const name = n.getAttribute('data-crate');
      n.addEventListener('mouseenter', () => focus(name));
      n.addEventListener('mouseleave', clear);
      n.addEventListener('click', (e) => { e.stopPropagation(); focus(name); });
    });
    graph.addEventListener('click', clear);
  }
})();
