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

        if (sidebar) sidebar.classList.toggle('open');
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

    // ---------- Star Rating ----------
    function initStarRatings() {
        const starContainers = document.querySelectorAll('.star-rating');

        starContainers.forEach(function (container) {
            const stars = container.querySelectorAll('.star');
            const hiddenInput = container.parentElement.querySelector('input[type="hidden"][name="rating"]');

            stars.forEach(function (star) {
                star.addEventListener('click', function () {
                    const value = parseInt(star.getAttribute('data-value'), 10);
                    if (isNaN(value)) return;

                    stars.forEach(function (s) {
                        const val = parseInt(s.getAttribute('data-value'), 10);
                        if (val <= value) {
                            s.classList.add('selected');
                        } else {
                            s.classList.remove('selected');
                        }
                    });

                    if (hiddenInput) {
                        hiddenInput.value = value;
                    }
                });

                star.addEventListener('mouseenter', function () {
                    const value = parseInt(star.getAttribute('data-value'), 10);
                    stars.forEach(function (s) {
                        const val = parseInt(s.getAttribute('data-value'), 10);
                        s.style.color = val <= value ? '#f59e0b' : '#d1d5db';
                    });
                });
            });

            container.addEventListener('mouseleave', function () {
                const selected = container.querySelector('.star.selected');
                const selectedVal = selected ? parseInt(selected.getAttribute('data-value'), 10) : 0;
                stars.forEach(function (s) {
                    const val = parseInt(s.getAttribute('data-value'), 10);
                    s.style.color = val <= selectedVal ? '#f59e0b' : '#d1d5db';
                });
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

    // ---------- Initialize ----------
    document.addEventListener('DOMContentLoaded', function () {
        autoDismissFlashes();
        initStarRatings();
        setCurrentYear();
        initConfirmActions();
    });
})();
