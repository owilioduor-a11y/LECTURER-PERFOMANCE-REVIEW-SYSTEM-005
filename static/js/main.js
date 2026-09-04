/**
 * Main JavaScript - University Lecturer Review System
 * Handles navigation, sidebar, flash messages, and star ratings
 */

(function () {
    'use strict';

    // ---------- Mobile Navigation ----------
    window.toggleMenu = function () {
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('sidebarOverlay');
        const navLinks = document.getElementById('navLinks');
        const navToggle = document.getElementById('navToggle');

        if (sidebar) {
            sidebar.classList.toggle('open');
            sidebar.setAttribute('aria-hidden', sidebar.classList.contains('open')
                ? 'false' : 'true');
        }
        if (overlay) overlay.classList.toggle('open');
        if (navLinks) navLinks.classList.toggle('open');

        if (navToggle) {
            const isOpen = sidebar ? sidebar.classList.contains('open') : navLinks.classList.contains('open');
            navToggle.setAttribute('aria-expanded', isOpen);
        }
    };

    // ---------- Flash Message Auto-dismiss ----------
    function autoDismissFlashes() {
        const flashes = document.querySelectorAll('.flash');
        flashes.forEach(function (flash) {
            setTimeout(function () {
                flash.style.opacity = '0';
                flash.style.transform = 'translateY(-10px)';
                flash.style.transition = 'opacity 0.3s, transform 0.3s';
                setTimeout(function () {
                    flash.remove();
                }, 300);
            }, 5000);
        });
    }

    // ---------- Star Rating (mouse + keyboard accessible) ----------
    function setStars(container, value) {
        const stars = container.querySelectorAll('.star');
        stars.forEach(function (s) {
            const val = parseInt(s.getAttribute('data-value'), 10);
            if (val <= value) {
                s.classList.add('selected');
                s.setAttribute('aria-pressed', 'true');
            } else {
                s.classList.remove('selected');
                s.setAttribute('aria-pressed', 'false');
            }
        });
    }

    function setHiddenInput(container, value) {
        const hiddenInput = container.parentElement.querySelector(
            'input[type="hidden"][name="rating"]'
        );
        if (hiddenInput) {
            hiddenInput.value = value;
        }
    }

    function initStarRatings() {
        const starContainers = document.querySelectorAll('.star-rating');

        starContainers.forEach(function (container) {
            const stars = container.querySelectorAll('.star');

            // Mouse interaction
            stars.forEach(function (star) {
                star.addEventListener('click', function () {
                    const value = parseInt(star.getAttribute('data-value'), 10);
                    if (isNaN(value)) return;
                    setStars(container, value);
                    setHiddenInput(container, value);
                });

                star.addEventListener('mouseenter', function () {
                    const value = parseInt(star.getAttribute('data-value'), 10);
                    stars.forEach(function (s) {
                        const val = parseInt(s.getAttribute('data-value'), 10);
                        s.style.color = val <= value ? '#b45309' : '#d1d5db';
                    });
                });
            });

            container.addEventListener('mouseleave', function () {
                const selected = container.querySelector('.star.selected');
                const selectedVal = selected ? parseInt(selected.getAttribute('data-value'), 10) : 0;
                stars.forEach(function (s) {
                    const val = parseInt(s.getAttribute('data-value'), 10);
                    s.style.color = val <= selectedVal ? '#b45309' : '#d1d5db';
                });
            });

            // Keyboard interaction (WCAG 2.1: every interactive control is keyboard operable)
            stars.forEach(function (star, index) {
                star.addEventListener('keydown', function (e) {
                    e.preventDefault();
                    let nextIndex;
                    if (e.key === 'ArrowRight' || e.key === 'ArrowUp') {
                        nextIndex = Math.min(index + 1, stars.length - 1);
                    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') {
                        nextIndex = Math.max(index - 1, 0);
                    } else if (e.key === 'Home') {
                        nextIndex = 0;
                    } else if (e.key === 'End') {
                        nextIndex = stars.length - 1;
                    } else if (e.key === 'Enter' || e.key === ' ') {
                        const value = index + 1;
                        setStars(container, value);
                        setHiddenInput(container, value);
                        return;
                    } else {
                        return;
                    }
                    stars[nextIndex].focus();
                });
            });

            // Set initial aria-pressed states
            stars.forEach(function (star) {
                star.setAttribute('aria-pressed', 'false');
            });
        });
    }

    // ---------- Current Year ----------
    function setCurrentYear() {
        const yearEls = document.querySelectorAll('#current-year');
        yearEls.forEach(function (el) {
            el.textContent = new Date().getFullYear();
        });
    }

    // ---------- Confirm Actions ----------
    function initConfirmActions() {
        document.querySelectorAll('[data-confirm]').forEach(function (el) {
            el.addEventListener('click', function (e) {
                const message = el.getAttribute('data-confirm') || 'Are you sure?';
                if (!confirm(message)) {
                    e.preventDefault();
                }
            });
        });
    }

    // ---------- Form Submit Loading ----------
    function initFormLoading() {
        document.querySelectorAll('form').forEach(function (form) {
            form.addEventListener('submit', function () {
                const btn = form.querySelector('button[type="submit"]');
                if (btn && !btn.classList.contains('loading')) {
                    btn.classList.add('loading');
                    btn.setAttribute('data-original-text', btn.textContent);
                }
            });
        });
    }

    // ---------- Dark Mode Toggle ----------
    function initTheme() {
        var saved = localStorage.getItem('theme');
        if (saved) {
            document.documentElement.setAttribute('data-theme', saved);
        } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            document.documentElement.setAttribute('data-theme', 'dark');
        }
    }

    window.toggleTheme = function () {
        var current = document.documentElement.getAttribute('data-theme');
        var next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('theme', next);
    };

    // ---------- Initialize ----------
    document.addEventListener('DOMContentLoaded', function () {
        initTheme();
        autoDismissFlashes();
        initStarRatings();
        setCurrentYear();
        initConfirmActions();
        initFormLoading();
    });
})();
