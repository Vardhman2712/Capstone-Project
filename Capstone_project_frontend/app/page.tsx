'use client';

import { useRouter } from 'next/navigation';
import { useAuth } from './context/AuthContext';
import Image from 'next/image';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import { useState, useEffect } from 'react';
import Review from '../public/review.jpg';
import Teacher from '../public/teacher.jpg';
import instructor from '../public/instructor.jpg';
import problem from '../public/problem.jpg';
import uplaodDocument from '../public/uploadingdocumentsThreeStudentsiilustration.jpg';

export default function HomePage() {
  const router = useRouter();
  const { user } = useAuth();
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    // Check if this is the first visit
    const hasVisited = localStorage.getItem('hasVisitedBefore');

    if (!hasVisited) {
      setIsLoading(true);
      localStorage.setItem('hasVisitedBefore', 'true');

      // Set loading to false after animation duration
      const timer = setTimeout(() => {
        setIsLoading(false);
      }, 2000);

      return () => clearTimeout(timer);
    }
  }, []);

  // Animation variants
  const fadeInUp = {
    initial: { y: 30, opacity: 0 },
    animate: { y: 0, opacity: 1 },
    transition: { duration: 0.5 }
  };

  const staggerContainer = {
    animate: {
      transition: {
        staggerChildren: 0.2
      }
    }
  };

  const shimmerEffect = {
    initial: { x: '-100%' },
    animate: {
      x: '100%',
      transition: {
        repeat: 0,
        duration: 1.5,
        ease: "easeInOut"
      }
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50/50 to-white/50">
      <AnimatePresence>
        {isLoading && (
          <motion.div
            initial={{ opacity: 1 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.5 }}
            className="fixed inset-0 bg-gradient-to-br from-teal-600 to-cyan-600 z-[9999] flex items-center justify-center pointer-events-none"
          >
            <motion.div
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.8, opacity: 0 }}
              transition={{ duration: 0.5 }}
              className="relative"
            >
              <svg className="w-20 h-20 text-white" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <motion.path
                  initial={{ pathLength: 0 }}
                  animate={{ pathLength: 1 }}
                  transition={{ duration: 1.5, ease: "easeInOut" }}
                  d="M12 4.75L19.25 9L12 13.25L4.75 9L12 4.75Z"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <motion.path
                  initial={{ pathLength: 0 }}
                  animate={{ pathLength: 1 }}
                  transition={{ duration: 1.5, ease: "easeInOut", delay: 0.5 }}
                  d="M4.75 15L12 19.25L19.25 15"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: '100%' }}
                transition={{ duration: 1, ease: "easeInOut", delay: 1 }}
                className="absolute -bottom-4 left-0 h-1 bg-white rounded-full"
              />
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Hero Section */}
        <motion.section
          variants={staggerContainer}
          initial="initial"
          animate="animate"
          className="py-12 md:py-20 relative"
        >
          {/* Background Elements */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 1, delay: 2.5 }}
            className="absolute inset-0 overflow-hidden"
          >
            <div className="absolute -top-40 -right-32 w-96 h-96 bg-teal-100 rounded-full opacity-20 blur-3xl"></div>
            <div className="absolute -bottom-40 -left-32 w-96 h-96 bg-cyan-100 rounded-full opacity-20 blur-3xl"></div>
          </motion.div>

          <div className="relative flex flex-col md:flex-row items-center justify-between gap-12 md:gap-16">
            {/* Text Content */}
            <motion.div
              variants={staggerContainer}
              className="text-center md:text-left max-w-xl w-full"
            >
              <motion.div
                variants={fadeInUp}
                className="inline-flex items-center px-4 py-2 bg-teal-50 rounded-full mb-6 text-sm text-teal-700 font-medium shadow-sm border border-teal-100/50"
              >
                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                Welcome to Capstone Portal
              </motion.div>

              <motion.h1
                variants={fadeInUp}
                className="text-4xl sm:text-5xl font-extrabold text-gray-900 mb-4 md:mb-6 tracking-tight leading-tight"
              >
                Transform Your Academic Journey
                <motion.span
                  variants={fadeInUp}
                  className="block text-transparent bg-clip-text bg-gradient-to-r from-teal-600 to-cyan-600 mt-2"
                >
                  With Capstone Portal
                </motion.span>
              </motion.h1>

              <motion.p
                variants={fadeInUp}
                className="text-base sm:text-lg text-gray-600 mb-8 md:mb-10 leading-relaxed max-w-lg mx-auto md:mx-0"
              >
                Elevate your capstone experience with our comprehensive platform. Seamlessly manage submissions, collaborate with peers, and achieve academic excellence.
              </motion.p>

              {user ? (
                <motion.div variants={fadeInUp}>
                  <Link
                    href="/dashboard"
                    className="inline-flex items-center justify-center bg-gradient-to-r from-teal-600 to-cyan-600 hover:from-teal-500 hover:to-cyan-500 text-white font-medium px-6 sm:px-8 py-3 sm:py-3.5 text-sm sm:text-base rounded-xl transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-[1.02] group relative overflow-hidden"
                  >
                    <span className="relative z-10">Go to Dashboard</span>
                    <svg className="w-4 h-4 ml-2 transform group-hover:translate-x-1 transition-transform duration-200 relative z-10" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                    </svg>
                    <motion.div
                      variants={shimmerEffect}
                      className="absolute inset-0 bg-gradient-to-r from-white/0 via-white/10 to-white/0"
                    />
                  </Link>
                </motion.div>
              ) : (
                <motion.div
                  variants={fadeInUp}
                  className="flex flex-col sm:flex-row gap-3 sm:gap-4 justify-center md:justify-start"
                >
                  <Link
                    href="/login"
                    className="inline-flex items-center justify-center bg-gradient-to-r from-teal-600 to-cyan-600 hover:from-teal-500 hover:to-cyan-500 text-white font-medium px-6 sm:px-8 py-3 sm:py-3.5 text-sm sm:text-base rounded-xl transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-[1.02] group relative overflow-hidden"
                  >
                    <span className="relative z-10">Get Started</span>
                    <svg className="w-4 h-4 ml-2 transform group-hover:translate-x-1 transition-transform duration-200 relative z-10" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                    </svg>
                    <motion.div
                      variants={shimmerEffect}
                      className="absolute inset-0 bg-gradient-to-r from-white/0 via-white/10 to-white/0"
                    />
                  </Link>
                  <Link
                    href="/register"
                    className="inline-flex items-center justify-center border-2 border-teal-600 text-teal-600 hover:bg-teal-50 font-medium px-6 sm:px-8 py-[10px] sm:py-[13px] text-sm sm:text-base rounded-xl transition-all duration-300 transform hover:scale-[1.02] group relative overflow-hidden"
                  >
                    <span className="relative z-10">Learn More</span>
                    <svg className="w-4 h-4 ml-2 opacity-0 group-hover:opacity-100 transform translate-x-[-10px] group-hover:translate-x-0 transition-all duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </Link>
                </motion.div>
              )}
            </motion.div>

            {/* Hero Image */}
            <motion.div
              initial={{ opacity: 0, x: 50 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6, delay: 0.5 }}
              className="w-full md:w-1/2 relative"
            >
              <div className="absolute inset-0 bg-gradient-to-r from-teal-100 to-cyan-100 rounded-2xl transform rotate-3"></div>
              <div className="relative bg-white rounded-2xl shadow-xl p-2">
                <Image
                  src={instructor}
                  alt="Teacher working on capstone projects"
                  className="rounded-xl shadow-lg w-full h-auto relative transform -rotate-3 transition-transform duration-300 hover:rotate-0"
                  placeholder="blur"
                  priority
                />
                {/* Floating Elements */}
                <motion.div
                  initial={{ opacity: 0, scale: 0.5 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.3, delay: 0.7 }}
                  className="absolute -top-6 -left-6 bg-white rounded-lg p-3 shadow-lg transform rotate-3 hover:rotate-0 transition-transform duration-300"
                >
                  <svg className="w-6 h-6 text-teal-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </motion.div>
                <motion.div
                  initial={{ opacity: 0, scale: 0.5 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.3, delay: 0.8 }}
                  className="absolute -bottom-6 -right-6 bg-white rounded-lg p-3 shadow-lg transform -rotate-6 hover:rotate-0 transition-transform duration-300"
                >
                  <svg className="w-6 h-6 text-cyan-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </motion.div>
              </div>
            </motion.div>
          </div>
        </motion.section>

        {/* Features Section */}
        <section className="py-16 md:py-24 bg-gradient-to-b from-gray-50 to-white rounded-3xl my-12 md:my-20 shadow-sm border border-gray-100 relative overflow-hidden">
          {/* Background Pattern */}
          <div className="absolute inset-0 bg-[url('/grid.svg')] opacity-[0.015]"></div>

          <div className="relative">
            <div className="text-center mb-12 md:mb-16 px-4">
              <div className="inline-flex items-center px-4 py-2 bg-gray-50 rounded-full mb-6 text-sm text-gray-700 font-medium border border-gray-200/50">
                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z" />
                </svg>
                Features & Capabilities
              </div>
              <h2 className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-gray-900 to-gray-700 bg-clip-text text-transparent mb-4">
                Powerful Features for Your Success
              </h2>
              <p className="text-base sm:text-lg text-gray-600 max-w-2xl mx-auto">
                Everything you need to manage, submit, and excel in your capstone projects
              </p>
            </div>

            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6 md:gap-8 px-4">
              {[
                {
                  title: 'Smart Project Management',
                  desc: 'Intuitive tools for creating, tracking, and managing capstone projects with real-time updates and progress monitoring.',
                  icon: (
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 sm:h-7 sm:w-7" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                    </svg>
                  ),
                  image: problem,
                  color: 'from-blue-500 to-indigo-500'
                },
                {
                  title: 'Seamless Submissions',
                  desc: 'Advanced file handling with smart compression, version control, and automatic formatting for professional documentation.',
                  icon: (
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 sm:h-7 sm:w-7" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10" />
                    </svg>
                  ),
                  image: uplaodDocument,
                  color: 'from-teal-500 to-cyan-500'
                },
                {
                  title: 'Secure Role Management',
                  desc: 'Comprehensive access control system with specialized features for students, teachers, and evaluators.',
                  icon: (
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 sm:h-7 sm:w-7" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                  ),
                  image: Teacher,
                  color: 'from-purple-500 to-pink-500'
                },
              ].map((feature, i) => (
                <div key={i} className="bg-white p-5 sm:p-6 rounded-2xl shadow-lg hover:shadow-xl transition-all duration-300 transform hover:-translate-y-1 border border-gray-100/80 group">
                  <div className="relative h-40 sm:h-48 mb-6 rounded-xl overflow-hidden">
                    <Image
                      src={feature.image}
                      alt={feature.title}
                      className="object-cover w-full h-full transform group-hover:scale-110 transition-transform duration-500"
                      width={400}
                      height={300}
                    />
                    <div className="absolute inset-0 bg-gradient-to-t from-black/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                  </div>
                  <div className="flex items-center gap-4 mb-4">
                    <div className={`w-10 h-10 sm:w-12 sm:h-12 bg-gradient-to-br ${feature.color} rounded-xl flex items-center justify-center text-white shadow-lg group-hover:shadow-xl transition-all duration-300 group-hover:scale-110`}>
                      {feature.icon}
                    </div>
                    <h3 className="text-lg sm:text-xl font-semibold text-gray-900">{feature.title}</h3>
                  </div>
                  <p className="text-gray-600 leading-relaxed text-sm sm:text-base">{feature.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* How It Works Section */}
        <section className="py-16 md:py-24 bg-gradient-to-b from-gray-900 to-gray-800 rounded-3xl text-white shadow-xl relative overflow-hidden">
          <div className="absolute inset-0 bg-[url('/grid.svg')] opacity-10" />
          <div className="absolute inset-0 bg-gradient-to-br from-teal-500/10 to-cyan-500/10" />

          <div className="relative">
            <div className="text-center mb-12 md:mb-16 px-4">
              <div className="inline-flex items-center px-4 py-2 bg-white/10 backdrop-blur-sm rounded-full mb-6 text-sm text-white/90 font-medium border border-white/10">
                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                How It Works
              </div>
              <h2 className="text-3xl md:text-4xl font-bold mb-4 bg-gradient-to-r from-white to-gray-300 bg-clip-text text-transparent">
                Simple & Effective Workflow
              </h2>
              <p className="text-gray-300 text-base sm:text-lg max-w-2xl mx-auto">
                Three easy steps to capstone success
              </p>
            </div>

            <div className="grid lg:grid-cols-2 gap-12 items-center px-4">
              {/* Steps */}
              <div className="space-y-8">
                {[
                  {
                    step: '01',
                    title: 'Project Creation & Assignment',
                    desc: 'Teachers easily create and customize projects, set guidelines, and assign teams with our intuitive interface.',
                    icon: (
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 sm:h-6 sm:w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                      </svg>
                    ),
                    color: 'from-blue-400 to-indigo-400'
                  },
                  {
                    step: '02',
                    title: 'Collaborative Development',
                    desc: 'Students work together, share resources, and submit their work through our streamlined submission system.',
                    icon: (
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 sm:h-6 sm:w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
                      </svg>
                    ),
                    color: 'from-teal-400 to-cyan-400'
                  },
                  {
                    step: '03',
                    title: 'Review & Certification',
                    desc: 'Faculty provides comprehensive feedback and issues digital certifications upon successful completion.',
                    icon: (
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 sm:h-6 sm:w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                    ),
                    color: 'from-purple-400 to-pink-400'
                  },
                ].map((item, i) => (
                  <div key={i} className="flex items-start gap-6 group">
                    <div className={`w-14 h-14 sm:w-16 sm:h-16 bg-gradient-to-br ${item.color} rounded-2xl flex items-center justify-center text-white text-lg sm:text-xl font-bold flex-shrink-0 shadow-lg group-hover:shadow-xl transition-all duration-300 transform group-hover:scale-110`}>
                      {item.step}
                    </div>
                    <div>
                      <h3 className="text-lg sm:text-xl font-semibold text-white mb-2 group-hover:text-teal-300 transition-colors duration-200">
                        {item.title}
                      </h3>
                      <p className="text-gray-300 leading-relaxed text-sm sm:text-base">{item.desc}</p>
                    </div>
                  </div>
                ))}
              </div>

              {/* Process Image */}
              <div className="relative">
                <div className="absolute inset-0 bg-gradient-to-r from-teal-400/20 to-cyan-400/20 rounded-2xl transform rotate-3"></div>
                <div className="relative bg-white/5 backdrop-blur-sm rounded-2xl p-2">
                  <Image
                    src={Review}
                    alt="Review and feedback process"
                    className="rounded-xl shadow-2xl w-full h-auto relative transform -rotate-3 transition-transform duration-300 hover:rotate-0"
                    placeholder="blur"
                  />
                  {/* Floating Elements */}
                  <div className="absolute -top-6 -left-6 bg-white/10 backdrop-blur-sm rounded-lg p-3 shadow-lg transform rotate-3 hover:rotate-0 transition-transform duration-300">
                    <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <div className="absolute -bottom-6 -right-6 bg-white/10 backdrop-blur-sm rounded-lg p-3 shadow-lg transform -rotate-6 hover:rotate-0 transition-transform duration-300">
                    <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                    </svg>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}