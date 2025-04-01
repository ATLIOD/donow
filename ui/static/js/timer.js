function timer(durationInMinutes) {
  return {
    expiry: null,
    remaining: 0,
    interval: null,
    sound: new Audio("/static/sounds/notification.mp3"),
    pausedTime: null,

    init() {
      this.reset(durationInMinutes);
    },

    reset(minutes) {
      this.stop(); // Ensure the timer stops before resetting
      this.expiry = new Date().getTime() + minutes * 60000;
      this.setRemaining();
      if (this.interval) clearInterval(this.interval);
      this.pausedTime = null;
    },

    start() {
      if (this.interval) clearInterval(this.interval); // Clear any existing interval
      this.expiry = new Date().getTime() + this.remaining * 1000;
      this.interval = setInterval(() => {
        this.setRemaining();
        if (this.remaining <= 0) {
          this.onEnd();
          this.stop();
          this.reset(durationInMinutes);
        }
      }, 1000);
    },

    stop() {
      clearInterval(this.interval);
      this.pausedTime = this.remaining;
    },

    resume() {
      if (this.pausedTime !== null) {
        this.expiry = new Date().getTime() + this.pausedTime * 1000;
        this.interval = setInterval(() => {
          this.setRemaining();
          if (this.remaining <= 0) {
            this.onEnd();
            this.stop();
            this.reset(durationInMinutes);
          }
        }, 1000);
        this.pausedTime = null;
      }
    },

    setRemaining() {
      const diff = this.expiry - new Date().getTime();
      this.remaining = Math.max(0, Math.floor(diff / 1000));
    },

    onEnd() {
      this.sound.play(); // Play notification sound
    },

    minutes() {
      return Math.floor(this.remaining / 60);
    },

    seconds() {
      return this.remaining % 60;
    },

    time() {
      return {
        minutes: ("0" + this.minutes()).slice(-2),
        seconds: ("0" + this.seconds()).slice(-2),
      };
    },
  };
}

// document.addEventListener("DOMContentLoaded", () => {
//   let timerInstance = Alpine.reactive(timer(studyTime));
//
//   document.getElementById("start").addEventListener("click", () => timerInstance.start());
//   document.getElementById("stop").addEventListener("click", () => timerInstance.stop());
//   document.getElementById("reset").addEventListener("click", () => timerInstance.init(studyTime));
// });
