"use client";

import { useState, useEffect } from "react";
import { adminApi } from "../api/api";
import { useRouter } from "next/navigation";

export const useApprovalStatus = () => {
  const [isApproved, setIsApproved] = useState<boolean | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    const checkApprovalStatus = async () => {
      try {
        const response = await adminApi.getUserApprovalStatus();
        setIsApproved(response.is_approved);

        // If not approved and not admin, show pending approval page
        if (!response.is_approved && response.role !== "admin") {
          router.push("/pending-approval");
        }
      } catch (error) {
        console.error("Error checking approval status:", error);
        setIsApproved(false);
      } finally {
        setIsLoading(false);
      }
    };

    checkApprovalStatus();
  }, [router]);

  return { isApproved, isLoading };
};
