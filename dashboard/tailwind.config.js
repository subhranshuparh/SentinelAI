/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // Dark by default per the spec — these are the *only* surface colours,
        // so a component that invents its own grey is immediately visible.
        ink: {
          900: '#0b0f16', // page
          800: '#121826', // card
          700: '#1b2334', // card border / raised
          600: '#2a3448', // hairline
        },
        // Risk tiers. Defined once so "red is reserved for genuinely high risk"
        // is enforced by the palette rather than by remembering it in each file.
        tier: {
          low: '#34d399',
          medium: '#fbbf24',
          high: '#fb923c',
          critical: '#f87171',
          unknown: '#94a3b8',
        },
      },
      fontSize: {
        // Nudged up across the board. Senior citizens are a named target user,
        // and a 12px dashboard excludes them before they read a word.
        xs: ['0.8125rem', '1.15rem'],
        sm: ['0.9375rem', '1.4rem'],
        base: ['1.0625rem', '1.6rem'],
      },
      // Custom keyframes that are referenced via animate-* utilities defined
      // in index.css @layer utilities. Tailwind must know about these names
      // so that the animate-* class references are not purged.
      animation: {
        'glow-pulse':     'glow-pulse 3s ease-in-out infinite',
        'fade-in-up':     'fade-in-up 0.5s ease-out forwards',
        'fade-in':        'fade-in 0.4s ease-out forwards',
        'slide-in-right': 'slide-in-right 0.4s ease-out forwards',
        'shimmer':        'shimmer 1.8s ease-in-out infinite',
      },
      keyframes: {
        'glow-pulse': {
          '0%, 100%': { opacity: '1', filter: 'drop-shadow(0 0 6px rgba(96,165,250,0.6))' },
          '50%':      { opacity: '0.8', filter: 'drop-shadow(0 0 14px rgba(96,165,250,0.95))' },
        },
        'fade-in-up': {
          from: { opacity: '0', transform: 'translateY(12px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        'fade-in': {
          from: { opacity: '0' },
          to:   { opacity: '1' },
        },
        'slide-in-right': {
          from: { opacity: '0', transform: 'translateX(16px)' },
          to:   { opacity: '1', transform: 'translateX(0)' },
        },
        shimmer: {
          '0%':   { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [],
}
