package fish.payara.healthcare.repository;

import fish.payara.healthcare.model.Patient;
import jakarta.enterprise.context.ApplicationScoped;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory patient repository for demo purposes.
 * In production, this would be backed by a real database.
 */
@ApplicationScoped
public class PatientRepository {

    private final Map<String, Patient> patients = new ConcurrentHashMap<>();

    public PatientRepository() {
        initializeSampleData();
    }

    private void initializeSampleData() {
        // Sample patients for demo
        Patient patient1 = Patient.create(
                "P-001", "Jane", "Doe", LocalDate.of(1985, 5, 15),
                "123-45-6789", "jane.doe@email.com", "555-0101", "123 Main St, Springfield",
                "O+", "Penicillin", "Hypertension", "Dr. Smith", "Cardiology"
        );

        Patient patient2 = Patient.create(
                "P-002", "John", "Smith", LocalDate.of(1978, 3, 22),
                "987-65-4321", "john.smith@email.com", "555-0102", "456 Oak Ave, Springfield",
                "A+", "None", "Diabetes Type 2", "Dr. Smith", "Cardiology"
        );

        Patient patient3 = Patient.create(
                "P-003", "Alice", "Johnson", LocalDate.of(1992, 11, 8),
                "456-78-9012", "alice.j@email.com", "555-0103", "789 Pine Rd, Springfield",
                "B-", "Latex", "Asthma", "Dr. Williams", "Emergency"
        );

        Patient patient4 = Patient.create(
                "P-004", "Robert", "Brown", LocalDate.of(1965, 7, 30),
                "321-54-9876", "rbrown@email.com", "555-0104", "321 Elm St, Springfield",
                "AB+", "Shellfish", "Coronary artery disease", "Dr. Smith", "Cardiology"
        );

        Patient patient5 = Patient.create(
                "P-005", "Emma", "Davis", LocalDate.of(1988, 9, 14),
                "654-32-1098", "emma.d@email.com", "555-0105", "555 Maple Ln, Springfield",
                "O-", "None", "None", "Dr. Williams", "Emergency"
        );

        patients.put(patient1.id(), patient1);
        patients.put(patient2.id(), patient2);
        patients.put(patient3.id(), patient3);
        patients.put(patient4.id(), patient4);
        patients.put(patient5.id(), patient5);
    }

    public List<Patient> findAll() {
        return new ArrayList<>(patients.values());
    }

    public Optional<Patient> findById(String id) {
        return Optional.ofNullable(patients.get(id));
    }

    public List<Patient> findByDepartment(String department) {
        return patients.values().stream()
                .filter(p -> department.equals(p.department()))
                .toList();
    }

    public List<Patient> findByDoctor(String doctorName) {
        return patients.values().stream()
                .filter(p -> doctorName.equals(p.assignedDoctor()))
                .toList();
    }

    public Patient save(Patient patient) {
        Patient toSave;
        if (patient.id() == null || patient.id().isEmpty()) {
            String newId = "P-" + String.format("%03d", patients.size() + 1);
            toSave = patient.withId(newId);
        } else {
            toSave = patient.withUpdatedTimestamp();
        }
        patients.put(toSave.id(), toSave);
        return toSave;
    }

    public void delete(String id) {
        patients.remove(id);
    }

    public boolean exists(String id) {
        return patients.containsKey(id);
    }

    public long count() {
        return patients.size();
    }
}
