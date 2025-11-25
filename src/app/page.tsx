import { redirect } from "next/navigation";

export default function Home() {
  const user = { name: "John Doe", role: "Administrator" };
  if (user) {
    redirect(`/users`);
  } else {
    redirect(`/login`);
  }
}
