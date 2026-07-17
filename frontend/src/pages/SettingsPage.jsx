import { useState } from "react";
import { useAuth } from "../context/AuthContext.jsx";
import { useToast } from "../components/Toast.jsx";

function SettingsPage() {
  const { user } = useAuth();
  const toast = useToast();
  const [company, setCompany] = useState(user?.company || "");
  const [industry, setIndustry] = useState("Software and technology");
  const [evidence, setEvidence] = useState("Verified findings");
  const [environment, setEnvironment] = useState("Staging");

  function handleSave() {
    toast("Settings saved");
  }

  return (
    <div className='view'>
      <div className='head'>
        <div>
          <h1>Workspace settings</h1>
          <p>Company profile, defaults, billing, and retention.</p>
        </div>
        <button className='btn primary' onClick={handleSave}>
          Save
        </button>
      </div>

      <div className='formlayout'>
        <main>
          <section className='formsection'>
            <h2>Company profile</h2>
            <div className='grid2'>
              <div className='field'>
                <label>Company</label>
                <div className='control'>
                  <input
                    value={company}
                    onChange={(e) => setCompany(e.target.value)}
                    placeholder='Company name'
                  />
                </div>
              </div>
              <div className='field'>
                <label>Industry</label>
                <div className='control'>
                  <select
                    value={industry}
                    onChange={(e) => setIndustry(e.target.value)}
                  >
                    <option>Software and technology</option>
                    <option>Financial services</option>
                    <option>Healthcare</option>
                    <option>Retail and ecommerce</option>
                    <option>Government and public sector</option>
                    <option>Education</option>
                    <option>Other</option>
                  </select>
                </div>
              </div>
            </div>
          </section>

          <section className='formsection'>
            <h2>Assessment defaults</h2>
            <div className='grid2'>
              <div className='field'>
                <label>Evidence</label>
                <div className='control'>
                  <select
                    value={evidence}
                    onChange={(e) => setEvidence(e.target.value)}
                  >
                    <option>Verified findings</option>
                    <option>Verified plus heuristic</option>
                    <option>Aggressive</option>
                  </select>
                </div>
              </div>
              <div className='field'>
                <label>Environment</label>
                <div className='control'>
                  <select
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value)}
                  >
                    <option>Staging</option>
                    <option>Production</option>
                    <option>Development</option>
                  </select>
                </div>
              </div>
            </div>
          </section>

          <section className='formsection'>
            <h2>Account</h2>
            <div className='grid2'>
              <div className='field'>
                <label>Work email</label>
                <div className='control'>
                  <input value={user?.email || ""} readOnly />
                </div>
              </div>
              <div className='field'>
                <label>Plan</label>
                <div className='control'>
                  <input value='Business' readOnly />
                </div>
              </div>
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}

export default SettingsPage;
