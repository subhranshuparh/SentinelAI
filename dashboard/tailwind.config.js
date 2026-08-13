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
    },
  },
  plugins: [],
}
