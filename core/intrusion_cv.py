import cv2
import threading


class IntrusionDetector:
    def __init__(self, alert_callback=None):
        # Load Haar Cascade for full body detection
        self.person_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_fullbody.xml"
        )
        self.cap = cv2.VideoCapture(0)  # Use default webcam
        self.running = False
        self.alert_callback = alert_callback  # Function to call on intrusion detected

    def start_detection(self):
        self.running = True
        threading.Thread(target=self._run, daemon=True).start()

    def stop_detection(self):
        self.running = False
        self.cap.release()
        cv2.destroyAllWindows()

    def _run(self):
        while self.running:
            ret, frame = self.cap.read()
            if not ret:
                break

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            persons = self.person_cascade.detectMultiScale(
                gray, scaleFactor=1.1, minNeighbors=5
            )

            for x, y, w, h in persons:
                # Draw rectangle around detected person
                cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 0), 2)
                if self.alert_callback:
                    self.alert_callback("Person detected!")

            cv2.imshow("GuardianAI - Intrusion Detection", frame)

            if cv2.waitKey(1) & 0xFF == ord("q"):
                self.stop_detection()
                break
