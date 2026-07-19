window.Capacitor = {
  Plugins: {
    Preferences: {
      async get({ key }) { return { value: localStorage.getItem(key) }; },
      async set({ key, value }) { localStorage.setItem(key, value); },
      async keys() { return { keys: Object.keys(localStorage) }; },
      async remove({ key }) { localStorage.removeItem(key); }
    }
  }
};
