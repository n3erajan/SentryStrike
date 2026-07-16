import { ArrowLeft, ShieldCheck } from "@phosphor-icons/react";
import { Link } from "react-router-dom";

function NotFoundPage() {
  return (
    <main className='grid min-h-dvh place-items-center bg-[#f6f9fd] px-5 font-sans text-[#172033]'>
      <div className='w-full max-w-xl border border-[#cbd5e3] bg-white p-8 sm:p-12'>
        <span className='grid size-10 place-items-center rounded-md bg-[#006de2] text-white'><ShieldCheck size={21} weight='bold' /></span>
        <span className='mt-8 block font-mono text-[10px] font-semibold text-[#006de2]'>404 / ROUTE NOT FOUND</span>
        <h1 className='mt-3 text-3xl font-semibold'>This page is outside the scan scope.</h1>
        <p className='mt-3 max-w-[50ch] text-[12px] leading-6 text-[#415166]'>The address may be incorrect or the page may have moved.</p>
        <Link to='/' className='mt-7 inline-flex min-h-9 items-center gap-2 rounded-md bg-[#006de2] px-3.5 text-[10px] font-semibold text-white no-underline transition hover:bg-[#004bb7]'><ArrowLeft size={14} weight='bold' />Return home</Link>
      </div>
    </main>
  );
}

export default NotFoundPage;
