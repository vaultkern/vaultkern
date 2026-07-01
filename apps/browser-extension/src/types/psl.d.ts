declare module "psl" {
  const psl: {
    get(domain: string): string | null;
  };

  export default psl;
}
