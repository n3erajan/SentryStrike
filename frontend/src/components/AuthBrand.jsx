import { motion } from 'motion/react'
import { AnimatedWords } from './motion/primitives.jsx'
import { fadeUp } from './motion/tokens.js'

function AuthBrand({ mode = 'login' }) {
  const register = mode === 'register'
  const request = mode === 'request'
  const heading = request
    ? 'Bring your web security work under one organization.'
    : register
      ? 'Complete your workspace invitation.'
      : 'Pick up your security work.'
  const sub = request
    ? 'A workspace keeps your applications, DAST scans, findings, and team access in one place.'
    : register
      ? 'Create your account with the invited email to enter the workspace and role included in your invitation.'
      : 'Return to your scans, AI-assisted findings, team discussions, and remediation progress.'
  const proof = request
    ? [
        ['Applications', 'Authorized targets'],
        ['Work', 'Scans, findings and fixes'],
        ['Team', 'Owner-managed invitations'],
      ]
    : register
      ? [
          ['Email', 'Fixed by the invitation'],
          ['Role', 'Included in the invitation'],
          ['Link', 'Valid for one signup'],
        ]
      : [
          ['Applications', 'Saved targets and history'],
          ['Findings', 'Evidence, comments and status'],
          ['Reports', 'Web, PDF and JSON'],
        ]

  return (
    <aside className='auth-art'>
      <motion.div
        className='auth-copy'
        initial='hidden'
        animate='visible'
        variants={{
          hidden: {},
          visible: {
            transition: { staggerChildren: 0.1, delayChildren: 0.18 },
          },
        }}
      >
        <AnimatedWords as='h2' text={heading} delay={0.18} />
        <motion.p variants={fadeUp}>{sub}</motion.p>
        <motion.div className='proof' variants={fadeUp}>
          {proof.map(([label, value]) => (
            <div key={label}>
              <span>{label}</span>
              <b>{value}</b>
            </div>
          ))}
        </motion.div>
      </motion.div>
    </aside>
  )
}

export default AuthBrand
