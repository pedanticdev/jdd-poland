package fish.payara.healthcare.repository;

import fish.payara.healthcare.model.Patient;
import jakarta.data.repository.CrudRepository;
import jakarta.data.repository.Repository;

import java.util.List;
import java.util.UUID;

/**
 * Jakarta Data repository for the Patient entity.
 * The implementation of this interface will be provided by the container.
 */
@Repository
public interface PatientRepository extends CrudRepository<Patient, UUID> {

    /**
     * Finds all patients in a specific department.
     * The implementation of this method is automatically provided by Jakarta Data.
     *
     * @param department The department to search for.
     * @return A list of patients in the specified department.
     */
    List<Patient> findByDepartment(String department);
}
