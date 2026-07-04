declare module "psl" {
  type ParsedDomain =
    | {
        input: string;
        tld: string | null;
        sld: string | null;
        domain: string | null;
        subdomain: string | null;
        listed: boolean;
      }
    | {
        input: string;
        error: {
          message: string;
          code: string;
        };
      };

  const psl: {
    get(domain: string): string | null;
    parse(domain: string): ParsedDomain;
  };

  export default psl;
}
